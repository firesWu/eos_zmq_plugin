/**
 *  @file
 *  @copyright defined in eos/LICENSE.txt
 *  @author cc32d9 <cc32d9@gmail.com>
 */
#include <eosio/zmq_plugin/zmq_plugin.hpp>
#include <string>
#include <zmq.hpp>
#include <fc/io/json.hpp>

#include <eosio/chain/trace.hpp>

namespace {
  const char* SENDER_BIND_OPT = "zmq-sender-bind";
  const char* SENDER_BIND_DEFAULT = "tcp://127.0.0.1:5556";
  const char* WHITELIST_OPT = "zmq-whitelist-account";
  
  const int32_t MSGTYPE_ACTION_TRACE = 0;
  const int32_t MSGTYPE_IRREVERSIBLE_BLOCK = 1;
  const int32_t MSGTYPE_FORK = 2;
  const int32_t MSGTYPE_ACCEPTED_BLOCK = 3;
  const int32_t MSGTYPE_FAILED_TX = 4;
  const int32_t MSGTYPE_BALANCE_RESOURCE = 5;
}

namespace eosio {
  using namespace chain;
  using namespace zmqplugin;
  using boost::signals2::scoped_connection;

  static appbase::abstract_plugin& _zmq_plugin = app().register_plugin<zmq_plugin>();

  static symbol core_symbol = symbol();

  #define CALL(api_name, api_handle, api_namespace, call_name) \
  {std::string("/v1/" #api_name "/" #call_name), \
    [api_handle](string, string body, url_response_callback cb) mutable { \
            try { \
              if (body.empty()) body = "{}"; \
              auto result = api_handle.call_name(fc::json::from_string(body).as<api_namespace::call_name ## _params>()); \
              cb(200, fc::json::to_string(result)); \
            } catch (...) { \
              http_plugin::handle_exception(#api_name, #call_name, body, cb); \
            } \
        }}

  #define CHAIN_RO_CALL(call_name) CALL(zmq, ro_api, zmq_apis::read_only, call_name)

  class zmq_plugin_impl {
  public:
    zmq::context_t  context;
    zmq::socket_t sender_socket;
    string socket_bind_str;
    chain_plugin*          chain_plug = nullptr;
    fc::microseconds       abi_serializer_max_time;
    std::set<name>         system_accounts;
    std::map<name,std::set<name>>  blacklist_actions;
    std::map<transaction_id_type, transaction_trace_ptr> cached_traces;
    uint32_t               _end_block = 0;
    
    bool                   use_whitelist = false;
    std::set<name>         whitelist_accounts;
    bool                   whitelist_matched;

    fc::optional<scoped_connection> applied_transaction_connection;
    fc::optional<scoped_connection> accepted_block_connection;
    fc::optional<scoped_connection> irreversible_block_connection;

    zmq_plugin_impl():
      context(1),
      sender_socket(context, ZMQ_PUSH)
    {
      std::vector<name> sys_acc_names = {
        chain::config::system_account_name,
        N(eosio.msig),  N(eosio.token),  N(eosio.ram), N(eosio.ramfee),
        N(eosio.stake), N(eosio.vpay), N(eosio.bpay), N(eosio.saving),
        N(eosio.names), N(eosio.forum), N(eosio), N(eosio.unregd)
      };

      for(name n : sys_acc_names) {
        system_accounts.insert(n);
      }

      blacklist_actions.emplace
        (std::make_pair(chain::config::system_account_name,
                        std::set<name>{ N(onblock) } ));
      blacklist_actions.emplace
        (std::make_pair(N(blocktwitter),
                        std::set<name>{ N(tweet) } ));
      blacklist_actions.emplace
        (std::make_pair(N(gu2tembqgage),
                        std::set<name>{ N(ddos) } ));
    }

    static void copy_inline_row(const chain::key_value_object& obj, vector<char>& data) {
      data.resize( obj.value.size() );
      memcpy( data.data(), obj.value.data(), obj.value.size() );
    }

    static optional<asset> get_balance_by_contract( const chainbase::database& db, name account, name contract, symbol_code symcode ){
      const auto &idx = db.get_index<key_value_index, by_scope_primary>();
      optional<asset> opt_bal;

      // get eos balance
      const auto* balance_t_id = db.find<chain::table_id_object, chain::by_code_scope_table>(boost::make_tuple( contract, account, N(accounts) ));
      if( balance_t_id != nullptr ) {
        auto bal_entry = idx.find(boost::make_tuple( balance_t_id->id, symcode ));
        if ( bal_entry != idx.end() ) {
          asset bal;
          fc::datastream<const char *> ds(bal_entry->value.data(), bal_entry->value.size());
          fc::raw::unpack(ds, bal);
          if( bal.get_symbol().valid() ) {
            opt_bal.emplace(bal);
          }
        }
      }
      return opt_bal;
    }

    static optional<int64_t> get_stake( const chainbase::database& db, name account, abi_serializer abis, const fc::microseconds abi_serializer_max_time ){
      const auto &idx = db.get_index<key_value_index, by_scope_primary>();
      optional<int64_t> opt_stake;

      const auto* balance_t_id = db.find<chain::table_id_object, chain::by_code_scope_table>(boost::make_tuple( N(eosio), N(eosio), N(voters) ));
      if( balance_t_id != nullptr ) {
        auto it = idx.find(boost::make_tuple( balance_t_id->id, account ));
        if ( it != idx.end() ) {
          vector<char> data;
          copy_inline_row(*it, data);
          auto voter_info = abis.binary_to_variant( "voter_info", data, abi_serializer_max_time, true );
          auto stake = voter_info["staked"].as<int64_t>();
          opt_stake.emplace(stake);
        }
      }
      return opt_stake;
    }

    static optional<asset> get_refund( const chainbase::database& db, name account, abi_serializer abis, const fc::microseconds abi_serializer_max_time ){
      const auto &idx = db.get_index<key_value_index, by_scope_primary>();
      optional<asset> opt_refund;

      const auto* balance_t_id = db.find<chain::table_id_object, chain::by_code_scope_table>(boost::make_tuple( N(eosio), account, N(refunds) ));
      if( balance_t_id != nullptr ) {
        auto it = idx.find(boost::make_tuple( balance_t_id->id, account ));
        if ( it != idx.end() ) {
          vector<char> data;
          copy_inline_row(*it, data);
          auto refund_info = abis.binary_to_variant( "refund_request", data, abi_serializer_max_time, true );
          auto refund = refund_info["net_amount"].as<asset>() + refund_info["cpu_amount"].as<asset>();
          opt_refund.emplace(refund);
        }
      }
      return opt_refund;
    }

    static optional<voter_info> get_voter_info( const chainbase::database& db, name account, abi_serializer abis, const fc::microseconds abi_serializer_max_time ){
      const auto &idx = db.get_index<key_value_index, by_scope_primary>();
      optional<voter_info> opt_voter_info;

      const auto* balance_t_id = db.find<chain::table_id_object, chain::by_code_scope_table>(boost::make_tuple( N(eosio), N(eosio), N(voters) ));
      if( balance_t_id != nullptr ) {
        auto it = idx.find(boost::make_tuple( balance_t_id->id, account ));
        if ( it != idx.end() ) {
          vector<char> data;
          copy_inline_row(*it, data);
          auto voter = (abis.binary_to_variant( "voter_info", data, abi_serializer_max_time, true ));
          opt_voter_info.emplace(voter_info{voter["owner"].as<name>(),voter["proxy"].as<name>(),
              voter["producers"].as<std::vector<account_name>>(),voter["staked"].as<int64_t>(),
              voter["last_vote_weight"].as<double>(),voter["proxied_vote_weight"].as<double>(),
              voter["is_proxy"].as<bool>()});
        }
      }
      return opt_voter_info;
    }

    void send_msg( const string content, int32_t msgtype, int32_t msgopts)
    {
      zmq::message_t message(content.length()+sizeof(msgtype)+sizeof(msgopts));
      unsigned char* ptr = (unsigned char*) message.data();
      memcpy(ptr, &msgtype, sizeof(msgtype));
      ptr += sizeof(msgtype);
      memcpy(ptr, &msgopts, sizeof(msgopts));
      ptr += sizeof(msgopts);
      memcpy(ptr, content.c_str(), content.length());
      sender_socket.send(message);
    }


    void on_applied_transaction( const transaction_trace_ptr& p )
    {
      if (p->receipt) {
        cached_traces[p->id] = p;
      }
    }


    void on_accepted_block(const block_state_ptr& block_state)
    {
      auto block_num = block_state->block->block_num();
      if ( _end_block >= block_num ) {
        // report a fork. All traces sent with higher block number are invalid.
        zmq_fork_block_object zfbo;
        zfbo.invalid_block_num = block_num;
        send_msg(fc::json::to_string(zfbo), MSGTYPE_FORK, 0);
      }

      _end_block = block_num;

      {
        zmq_accepted_block_object zabo;
        zabo.accepted_block_num = block_num;
        zabo.accepted_block_timestamp = block_state->block->timestamp;
        zabo.accepted_block_producer = block_state->header.producer;
        zabo.accepted_block_digest = block_state->block->digest();
        send_msg(fc::json::to_string(zabo), MSGTYPE_ACCEPTED_BLOCK, 0);
      }

      for (auto& r : block_state->block->transactions) {
        transaction_id_type id;
        if (r.trx.contains<transaction_id_type>()) {
          id = r.trx.get<transaction_id_type>();
        }
        else {
          id = r.trx.get<packed_transaction>().id();
        }

        if( r.status == transaction_receipt_header::executed ) {
          // Send traces only for executed transactions
          auto it = cached_traces.find(id);
          if (it == cached_traces.end() || !it->second->receipt) {
            ilog("missing trace for transaction {id}", ("id", id));
            continue;
          }

          for( const auto& atrace : it->second->action_traces ) {
            if( atrace.receiver == atrace.act.account ) {
              on_action_trace( atrace, block_state );
            }  
          }
        }
        else {
          // Notify about a failed transaction
          zmq_failed_transaction_object zfto;
          zfto.trx_id = id.str();
          zfto.block_num = block_num;
          zfto.status_name = r.status;
          zfto.status_int = static_cast<uint8_t>(r.status);
          send_msg(fc::json::to_string(zfto), MSGTYPE_FAILED_TX, 0);
        }
      }

      cached_traces.clear();
    }


    void on_action_trace( const action_trace& at, const block_state_ptr& block_state )
    {
      whitelist_matched = false;
        
      // check the action against the blacklist
      auto search_acc = blacklist_actions.find(at.act.account);
      if(search_acc != blacklist_actions.end()) {
        if( search_acc->second.count(at.act.name) != 0 ) {
          return;
        }
      }

      auto& chain = chain_plug->chain();

      zmq_action_object zao;
      zao.global_action_seq = at.receipt->global_sequence;
      zao.block_num = block_state->block->block_num();
      zao.block_time = block_state->block->timestamp;
      zao.action_trace = chain.to_variant_with_abi(at, abi_serializer_max_time);

      std::set<name> accounts;
      assetmoves asset_moves;

      find_accounts_and_tokens(at, accounts, asset_moves);

      if( use_whitelist && !whitelist_matched ) {
        for (auto accit = accounts.begin(); !whitelist_matched && accit != accounts.end(); ++accit) {
          check_whitelist(*accit);
        }

        if( !whitelist_matched )
          return;
      }
        
      const auto& rm = chain.get_resource_limits_manager();

      // populate resource_balances
      // for (auto accit = accounts.begin(); accit != accounts.end(); ++accit) {
      //   name account_name = *accit;
      //   if( is_account_of_interest(account_name) ) {
      //     resource_balance bal;
      //     bal.account_name = account_name;
      //     rm.get_account_limits( account_name, bal.ram_quota, bal.net_weight, bal.cpu_weight );
      //     bool grelisted = chain.is_resource_greylisted(account_name);
      //     bal.net_limit = rm.get_account_net_limit_ex( account_name, !grelisted);
      //     bal.cpu_limit = rm.get_account_cpu_limit_ex( account_name, !grelisted);
      //     bal.ram_usage = rm.get_account_ram_usage( account_name );
      //     zao.resource_balances.emplace_back(bal);
      //   }
      // }

      const auto& db = chain.db();
      const auto& code_account = db.get<account_object,by_name>( config::system_account_name );
      const auto &idx = db.get_index<key_value_index, by_scope_primary>();

      // populate voter_infos
      for (auto accit = accounts.begin(); accit != accounts.end(); ++accit) {
        name account_name = *accit;
        abi_def abi;
        if( abi_serializer::to_abi(code_account.abi, abi) ) {
          try{
            abi_serializer abis( abi, abi_serializer_max_time );
            auto opt_voter_info = zmq_plugin_impl::get_voter_info(db, account_name, abis, abi_serializer_max_time);
            if( opt_voter_info.valid() ) zao.voter_infos.emplace_back(*opt_voter_info);
          } catch (fc::exception e) {
            elog("get voter info failed: ${details}, account: ${acc}",("details",e.what())("acc",account_name));
          } catch (...){
            elog("get voter info failed: ",("acc",account_name));
          }
        }
      }

      // populate token balances
      for (auto ctrit = asset_moves.begin(); ctrit != asset_moves.end(); ++ctrit) {
        account_name token_code = ctrit->first;
        for (auto symit = ctrit->second.begin(); symit != ctrit->second.end(); ++symit) {
          symbol sym = symit->first;
          uint64_t symcode = sym.to_symbol_code().value;
          // found the currency in stat table, assuming this is a valid token
          // get the balance for every account
          for( auto accitr = symit->second.begin(); accitr != symit->second.end(); ++accitr ) {
            account_name account_name = *accitr;

            // ilog("${contract} ${sym} ${acc}",("contract",token_code)("sym",sym)("acc",account_name));
            if( is_account_of_interest(account_name) ) {
              try{
                bool found = false;
                auto opt_bal= get_balance_by_contract( db, account_name, token_code, sym.to_symbol_code() );
                asset bal = asset(0, sym);
                asset stake = asset(0, sym);
                asset refund = asset(0, sym);
                if( opt_bal.valid() ){
                  found = true;
                  bal = *opt_bal;
                } 

                if( token_code == N(eosio.token)){
                  abi_def abi;
                  if( abi_serializer::to_abi(code_account.abi, abi) ) {
                    abi_serializer abis( abi, abi_serializer_max_time );
                    auto opt_stake = get_stake(db, account_name, abis, abi_serializer_max_time);
                    if( opt_stake.valid() ){
                      found = true;
                      stake = asset(*opt_stake, bal.get_symbol());
                    }
                    auto opt_refund = get_refund(db, account_name, abis, abi_serializer_max_time);
                    if( opt_refund.valid() ){
                      found = true;
                      refund = *opt_refund;
                    }
                  }
                }

                if( found ) {
                  zao.currency_balances.emplace_back(currency_balance{account_name, token_code, bal, stake, refund});
                } else {
                  // assume the balance was emptied and the table entry was deleted
                  zao.currency_balances.emplace_back(currency_balance{account_name, token_code, asset(0, sym), asset(0, sym), asset(0, sym), true});
                }
              } catch (fc::exception e) {
                elog("get voter info failed: ${details}, account: ${acc}",("details",e.what())("acc",account_name));
              } catch (...){
                elog("get voter info failed: ",("acc",account_name));
              }
            }
          }
        }
      }

      zao.last_irreversible_block = chain.last_irreversible_block_num();
      send_msg(fc::json::to_string(zao), MSGTYPE_ACTION_TRACE, 0);
    }


    void on_irreversible_block( const chain::block_state_ptr& bs )
    {
      zmq_irreversible_block_object zibo;
      zibo.irreversible_block_num = bs->block->block_num();
      zibo.irreversible_block_digest = bs->block->digest();
      send_msg(fc::json::to_string(zibo), MSGTYPE_IRREVERSIBLE_BLOCK, 0);
    }


    void inline add_asset_move(assetmoves& asset_moves, account_name contract,
                               symbol symbol, account_name owner)
    {
      asset_moves[contract][symbol].insert(owner);
      check_whitelist(owner);
    }


    void inline check_whitelist(account_name account)
    {
      if( use_whitelist && !whitelist_matched && whitelist_accounts.count(account) > 0 )
        whitelist_matched = true;
    }

    
    void find_accounts_and_tokens(const action_trace& at,
                                  std::set<name>& accounts,
                                  assetmoves& asset_moves)
    {      
      // accounts.insert(at.act.account);

      // if( at.receipt.receiver != at.act.account ) {
      //   accounts.insert(at.receipt.receiver);
      // }

      // for(permission_level p : at.act.authorization) {
      //   accounts.insert(p.actor);
      // }

      try{
        if( at.act.account == config::system_account_name ) {
          switch((uint64_t) at.act.name) {
          case N(newaccount):
            {
              const auto data = fc::raw::unpack<chain::newaccount>(at.act.data);
              accounts.insert(data.name);
            }
            break;
          case N(setcode):
            {
              // const auto data = fc::raw::unpack<chain::setcode>(at.act.data);
              // accounts.insert(data.account);
            }
            break;
          case N(setabi):
            {
              // const auto data = fc::raw::unpack<chain::setabi>(at.act.data);
              // accounts.insert(data.account);
            }
            break;
          case N(updateauth):
            {
              // const auto data = fc::raw::unpack<chain::updateauth>(at.act.data);
              // accounts.insert(data.account);
            }
            break;
          case N(deleteauth):
            {
              // const auto data = fc::raw::unpack<chain::deleteauth>(at.act.data);
              // accounts.insert(data.account);
            }
            break;
          case N(linkauth):
            {
              // const auto data = fc::raw::unpack<chain::linkauth>(at.act.data);
              // accounts.insert(data.account);
            }
            break;
          case N(unlinkauth):
            {
              // const auto data = fc::raw::unpack<chain::unlinkauth>(at.act.data);
              // accounts.insert(data.account);
            }
            break;
          case N(buyrambytes):
            {
              // const auto data = fc::raw::unpack<zmqplugin::syscontract::buyrambytes>(at.act.data);
              // accounts.insert(data.payer);
              // if( data.receiver != data.payer ) {
              //   accounts.insert(data.receiver);
              // }
            }
            break;
          case N(buyram):
            {
              // const auto data = fc::raw::unpack<zmqplugin::syscontract::buyram>(at.act.data);
              // accounts.insert(data.payer);
              // if( data.receiver != data.payer ) {
              //   accounts.insert(data.receiver);
              // }
            }
            break;
          case N(sellram):
            {
              // const auto data = fc::raw::unpack<zmqplugin::syscontract::sellram>(at.act.data);
              // accounts.insert(data.account);
            }
            break;
          case N(delegatebw):
            {
              const auto data = fc::raw::unpack<zmqplugin::syscontract::delegatebw>(at.act.data);
              accounts.insert(data.from);
              if( data.receiver != data.from ) {
                accounts.insert(data.receiver);
              }

              add_asset_move(asset_moves, N(eosio.token), core_symbol, data.from);
              add_asset_move(asset_moves, N(eosio.token), core_symbol, data.receiver);
            }
            break;
          case N(undelegatebw):
            {
              const auto data = fc::raw::unpack<zmqplugin::syscontract::undelegatebw>(at.act.data);
              accounts.insert(data.from);
              if( data.receiver != data.from ) {
                accounts.insert(data.receiver);
              }

              add_asset_move(asset_moves, N(eosio.token), core_symbol, data.from);
              add_asset_move(asset_moves, N(eosio.token), core_symbol, data.receiver);
            }
            break;
          case N(refund):
            {
              // const auto data = fc::raw::unpack<zmqplugin::syscontract::refund>(at.act.data);
              // accounts.insert(data.owner);
            }
            break;
          case N(withdraw):
            {
              const auto data = fc::raw::unpack<zmqplugin::syscontract::withdraw>(at.act.data);
              accounts.insert(data.owner);

              add_asset_move(asset_moves, N(eosio.token), core_symbol, data.owner);
            }
            break;
          case N(buyrex):
            {
              const auto data = fc::raw::unpack<zmqplugin::syscontract::buyrex>(at.act.data);
              accounts.insert(data.from);

              add_asset_move(asset_moves, N(eosio.token), core_symbol, data.from);
            }
            break;
          case N(unstaketorex):
            {
              const auto data = fc::raw::unpack<zmqplugin::syscontract::unstaketorex>(at.act.data);
              accounts.insert(data.owner);
              if( data.receiver != data.receiver ) {
                accounts.insert(data.receiver);
              }

              add_asset_move(asset_moves, N(eosio.token), core_symbol, data.owner);
              add_asset_move(asset_moves, N(eosio.token), core_symbol, data.receiver);
            }
            break;
          case N(sellrex):
            {
              const auto data = fc::raw::unpack<zmqplugin::syscontract::sellrex>(at.act.data);
              accounts.insert(data.from);

              add_asset_move(asset_moves, N(eosio.token), core_symbol, data.from);
            }
            break;
          case N(updaterex):
            {
              const auto data = fc::raw::unpack<zmqplugin::syscontract::updaterex>(at.act.data);
              accounts.insert(data.owner);

              add_asset_move(asset_moves, N(eosio.token), core_symbol, data.owner);
            }
            break;
          case N(consolidate):
            {
              const auto data = fc::raw::unpack<zmqplugin::syscontract::consolidate>(at.act.data);
              accounts.insert(data.owner);

              add_asset_move(asset_moves, N(eosio.token), core_symbol, data.owner);
            }
            break;
          case N(mvtosavings):
            {
              const auto data = fc::raw::unpack<zmqplugin::syscontract::mvtosavings>(at.act.data);
              accounts.insert(data.owner);

              add_asset_move(asset_moves, N(eosio.token), core_symbol, data.owner);
            }
            break;
          case N(mvfrsavings):
            {
              const auto data = fc::raw::unpack<zmqplugin::syscontract::mvfrsavings>(at.act.data);
              accounts.insert(data.owner);

              add_asset_move(asset_moves, N(eosio.token), core_symbol, data.owner);
            }
            break;
          case N(closerex):
            {
              const auto data = fc::raw::unpack<zmqplugin::syscontract::closerex>(at.act.data);
              accounts.insert(data.owner);

              add_asset_move(asset_moves, N(eosio.token), core_symbol, data.owner);
            }
            break;
          case N(regproducer):
            {
              const auto data = fc::raw::unpack<zmqplugin::syscontract::regproducer>(at.act.data);
              accounts.insert(data.producer);
            }
            break;
          case N(bidname):
            {
              // do nothing because newname account does not exist yet
            }
            break;
          case N(unregprod):
            {
              const auto data = fc::raw::unpack<zmqplugin::syscontract::unregprod>(at.act.data);
              accounts.insert(data.producer);
            }
            break;
          case N(regproxy):
            {
              const auto data = fc::raw::unpack<zmqplugin::syscontract::regproxy>(at.act.data);
              accounts.insert(data.proxy);
            }
            break;
          case N(voteproducer):
            {
              const auto data = fc::raw::unpack<zmqplugin::syscontract::voteproducer>(at.act.data);
              accounts.insert(data.voter);
              if( data.proxy ) {
                accounts.insert(data.proxy);
              }
              // not including producers list, although some projects may need it
            }
            break;
          case N(claimrewards):
            {
              // const auto data = fc::raw::unpack<zmqplugin::syscontract::claimrewards>(at.act.data);
              // accounts.insert(data.owner);
            }
            break;
          }
        }

        switch((uint64_t) at.act.name) {
        case N(transfer):
          {
            const auto data = fc::raw::unpack<zmqplugin::token::transfer>(at.act.data);
            // accounts.insert(data.from);
            // accounts.insert(data.to);

            symbol s = data.quantity.get_symbol();
            if( s.valid() ) {
              add_asset_move(asset_moves, at.act.account, s, data.from);
              add_asset_move(asset_moves, at.act.account, s, data.to);
            }
          }
          break;
        case N(issue):
          {
            const auto data = fc::raw::unpack<zmqplugin::token::issue>(at.act.data);
            // accounts.insert(data.to);

            symbol s = data.quantity.get_symbol();
            if( s.valid() ) {
              add_asset_move(asset_moves, at.act.account, s, data.to);
            }
          }
          break;
        case N(open):
          {
            const auto data = fc::raw::unpack<zmqplugin::token::open>(at.act.data);
            if( data.symbol.valid() ) {
              add_asset_move(asset_moves, at.act.account, data.symbol, data.owner);
            }
          }
          break;
        }
      } catch(fc::exception& e) {
        wlog("account: ${account}, action: ${action}, details: ${details}",("account",at.act.account)("action",at.act.name)("details",e.to_detail_string()));
      } catch(...){
        wlog("account: ${account}, action: ${action}",("account",at.act.account)("action",at.act.name));
      }
      

      // for( const auto& iline : at.inline_traces ) {
      //   find_accounts_and_tokens( iline, accounts, asset_moves );
      // }
    }


    bool is_account_of_interest(name account_name)
    {
      auto search = system_accounts.find(account_name);
      if(search != system_accounts.end()) {
        return false;
      }
      return true;
    }
  };

  namespace zmq_apis{
  using namespace eosio;
  using namespace zmqplugin;

  class read_only {
     const controller& ct;
     const fc::microseconds abi_serializer_max_time;
     bool  shorten_abi_errors = true;
     std::shared_ptr<zmq_plugin_impl> zmq_impl;

  public:

     read_only(const controller& ct, const fc::microseconds& abi_serializer_max_time, std::shared_ptr<zmq_plugin_impl> zmq_impl)
        : ct(ct), abi_serializer_max_time(abi_serializer_max_time),zmq_impl(zmq_impl) {}

     struct token_params {
        account_name     contract;
        symbol_code     symbol;
     };

     struct get_accounts_balance_params{
        vector<token_params> tokens;
     };

     struct get_accounts_balance_result{
        string result;
     };

     get_accounts_balance_result get_accounts_balance( const get_accounts_balance_params& p )const;

     struct get_balance_by_account_params{
        account_name account;
        vector<token_params> tokens;
     };

     struct get_balance_by_account_result{
        string result;
     };

     get_balance_by_account_result get_balance_by_account( const get_balance_by_account_params& p )const;

     void get_currency_by_account(zmq_accounts_info_object& zai, name account, name contract, symbol_code symcode, abi_serializer abis, const fc::microseconds abi_serializer_max_time)const;

     resource_balance get_resource_by_account(name account)const;
  };

  }


  zmq_plugin::zmq_plugin():my(new zmq_plugin_impl()){}
  zmq_plugin::~zmq_plugin(){}

  void zmq_plugin::set_program_options(options_description&, options_description& cfg)
  {
    cfg.add_options()
      (SENDER_BIND_OPT, bpo::value<string>()->default_value(SENDER_BIND_DEFAULT),
       "ZMQ Sender Socket binding");
    cfg.add_options()
      (WHITELIST_OPT, bpo::value<vector<string>>()->composing(),
       "ZMQ plugin whitelist of contracts to track");
  }

  void zmq_plugin::plugin_initialize(const variables_map& options)
  {
    my->socket_bind_str = options.at(SENDER_BIND_OPT).as<string>();
    if (my->socket_bind_str.empty()) {
      wlog("zmq-sender-bind not specified => eosio::zmq_plugin disabled.");
      return;
    }

    if( options.count(WHITELIST_OPT) > 0 ) {
      my->use_whitelist = true;
      auto whl = options.at(WHITELIST_OPT).as<vector<string>>();
      for( auto& whlname: whl ) {
        my->whitelist_accounts.insert(eosio::name(whlname));
      }
    }
    
    ilog("Binding to ZMQ PUSH socket ${u}", ("u", my->socket_bind_str));
    my->sender_socket.bind(my->socket_bind_str);

    my->chain_plug = app().find_plugin<chain_plugin>();
    my->abi_serializer_max_time = my->chain_plug->get_abi_serializer_max_time();

    auto& chain = my->chain_plug->chain();

    my->applied_transaction_connection.emplace
      ( chain.applied_transaction.connect( [&]( std::tuple<const transaction_trace_ptr&, const signed_transaction&> t ){
          my->on_applied_transaction( std::get<0>(t) );  }));

    my->accepted_block_connection.emplace
      ( chain.accepted_block.connect([&](const block_state_ptr& p) {
          my->on_accepted_block(p); }));

    my->irreversible_block_connection.emplace
      ( chain.irreversible_block.connect( [&]( const chain::block_state_ptr& bs ) {
          my->on_irreversible_block( bs ); } ));
  }

  void zmq_plugin::plugin_startup() {
    auto ro_api = zmq_apis::read_only(my->chain_plug->chain(),my->chain_plug->get_abi_serializer_max_time(), my);

    app().get_plugin<http_plugin>().add_api({
        CHAIN_RO_CALL(get_accounts_balance),
        CHAIN_RO_CALL(get_balance_by_account)
    });
  }

  void zmq_plugin::plugin_shutdown() {
    if( ! my->socket_bind_str.empty() ) {
      my->sender_socket.disconnect(my->socket_bind_str);
      my->sender_socket.close();
    }
  }

  namespace zmq_apis{

    read_only::get_accounts_balance_result read_only::get_accounts_balance( const read_only::get_accounts_balance_params& p )const{
      zmq_accounts_info_object zai;
      const auto& code_account = ct.db().get<account_object,by_name>( config::system_account_name );
      abi_def abi;
      
      if( !abi_serializer::to_abi(code_account.abi, abi) ) return read_only::get_accounts_balance_result{"ok"};;
      abi_serializer abis( abi, abi_serializer_max_time );

      uint64_t account_parse_counter = 1;
      const auto &account_list = ct.db().get_index<account_index,by_id>();
      for(auto itr = account_list.begin(); itr != account_list.end(); itr++, account_parse_counter++){
        auto account = itr->name;

        auto opt_voter_info = zmq_plugin_impl::get_voter_info(ct.db(), account, abis, abi_serializer_max_time);
        if( opt_voter_info.valid() ) zai.voter_infos.emplace_back(*opt_voter_info);
        // zai.resource_balances.emplace_back(get_resource_by_account(account));
        uint64_t counter = 1;
        for(auto t_itr = p.tokens.begin(); t_itr != p.tokens.end(); t_itr++,counter++){
          get_currency_by_account(zai, account, t_itr->contract, t_itr->symbol,abis, abi_serializer_max_time);
          if( counter%100==0 && (zai.voter_infos.size() !=0 || zai.currency_balances.size() != 0)){
            zmq_impl->send_msg(fc::json::to_string(zai), MSGTYPE_BALANCE_RESOURCE, 0);
            zai.voter_infos.clear();
            zai.currency_balances.clear();
          }
        }

        if( zai.voter_infos.size() !=0 || zai.currency_balances.size() != 0){
          zmq_impl->send_msg(fc::json::to_string(zai), MSGTYPE_BALANCE_RESOURCE, 0);
          zai.voter_infos.clear();
          zai.currency_balances.clear();
        }

        if( account_parse_counter % 10000 == 0 ){
          ilog(" parse accounts' token process: ${counter}",("counter",account_parse_counter));
        }
      }
      ilog(" parse accounts' token process: ${counter}",("counter",account_parse_counter));
      return read_only::get_accounts_balance_result{"ok"};
    }

    read_only::get_balance_by_account_result read_only::get_balance_by_account( const read_only::get_balance_by_account_params& p )const{
      zmq_accounts_info_object zai;
      const auto& code_account = ct.db().get<account_object,by_name>( config::system_account_name );
      abi_def abi;

      if( !abi_serializer::to_abi(code_account.abi, abi) ) return read_only::get_balance_by_account_result{"ok"};
      abi_serializer abis( abi, abi_serializer_max_time );
      auto opt_voter_info = zmq_plugin_impl::get_voter_info(ct.db(), p.account, abis, abi_serializer_max_time );
      if( opt_voter_info.valid() ) zai.voter_infos.emplace_back(*opt_voter_info);

      // zai.resource_balances.emplace_back(get_resource_by_account(p.account));
      for(auto itr = p.tokens.begin(); itr != p.tokens.end(); itr++){
        get_currency_by_account(zai, p.account, itr->contract, itr->symbol, abis, abi_serializer_max_time);
      }
      zmq_impl->send_msg(fc::json::to_string(zai), MSGTYPE_BALANCE_RESOURCE, 0);
      return read_only::get_balance_by_account_result{"ok"};
    }

    void read_only::get_currency_by_account(zmq_accounts_info_object& zai, name account, name contract, symbol_code symcode, abi_serializer abis, const fc::microseconds abi_serializer_max_time)const{
      const auto& db = ct.db();
      const auto &idx = db.get_index<key_value_index, by_scope_primary>();

      asset bal = asset(0, core_symbol);
      asset stake = asset(0, core_symbol);
      asset refund = asset(0, core_symbol);
      bool found = false;
      // get eos balance
      auto opt_bal = zmq_plugin_impl::get_balance_by_contract(db, account, contract, symcode );
      if( opt_bal.valid() ) {
        found = true;
        bal = *opt_bal;
      }

      if( contract == N(eosio.token)){
        auto opt_stake = zmq_plugin_impl::get_stake(db, account, abis, abi_serializer_max_time);
        if( opt_stake.valid() ){
          found = true;
          stake = asset(*opt_stake, bal.get_symbol());
        }

        auto opt_refund = zmq_plugin_impl::get_refund(db, account, abis, abi_serializer_max_time);
        if( opt_refund.valid() ){
          found = true;
          refund = *opt_refund;
        }
      } else if(found) {
        stake = asset(0, bal.get_symbol());
        refund = asset(0, bal.get_symbol());
      }

      if(found){
        zai.currency_balances.emplace_back( currency_balance{account, contract, bal, stake, refund} );
      }
    }

    resource_balance read_only::get_resource_by_account(name account)const{
      const auto& rm = ct.get_resource_limits_manager();

      resource_balance bal;
      bal.account_name = account;
      rm.get_account_limits( account, bal.ram_quota, bal.net_weight, bal.cpu_weight );
      bool grelisted = ct.is_resource_greylisted(account);
      bal.net_limit = rm.get_account_net_limit_ex( account, !grelisted);
      bal.cpu_limit = rm.get_account_cpu_limit_ex( account, !grelisted);
      bal.ram_usage = rm.get_account_ram_usage( account );
      return bal;
    }

  }
}

FC_REFLECT( zmqplugin::syscontract::buyrambytes,
            (payer)(receiver)(bytes) )

FC_REFLECT( zmqplugin::syscontract::buyram,
            (payer)(receiver)(quant) )

FC_REFLECT( zmqplugin::syscontract::sellram,
            (account)(bytes) )

FC_REFLECT( zmqplugin::syscontract::delegatebw,
            (from)(receiver)(stake_net_quantity)(stake_cpu_quantity)(transfer) )

FC_REFLECT( zmqplugin::syscontract::undelegatebw,
            (from)(receiver)(unstake_net_quantity)(unstake_cpu_quantity) )

FC_REFLECT( zmqplugin::syscontract::refund,
            (owner) )

// rex
FC_REFLECT( zmqplugin::syscontract::withdraw,
            (owner)(amount) )

FC_REFLECT( zmqplugin::syscontract::buyrex,
            (from)(amount) )

FC_REFLECT( zmqplugin::syscontract::unstaketorex,
            (owner)(receiver)(from_net)(from_cpu) )

FC_REFLECT( zmqplugin::syscontract::sellrex,
            (from)(rex) )

FC_REFLECT( zmqplugin::syscontract::updaterex,
            (owner) )

FC_REFLECT( zmqplugin::syscontract::consolidate,
            (owner) )

FC_REFLECT( zmqplugin::syscontract::mvtosavings,
            (owner)(rex) )

FC_REFLECT( zmqplugin::syscontract::mvfrsavings,
            (owner)(rex) )

FC_REFLECT( zmqplugin::syscontract::closerex,
            (owner) )

FC_REFLECT( zmqplugin::syscontract::regproducer,
            (producer)(producer_key)(url)(location) )

FC_REFLECT( zmqplugin::syscontract::unregprod,
            (producer) )

FC_REFLECT( zmqplugin::syscontract::regproxy,
            (proxy)(isproxy) )

FC_REFLECT( zmqplugin::syscontract::voteproducer,
            (voter)(proxy)(producers) )

FC_REFLECT( zmqplugin::syscontract::claimrewards,
            (owner) )

FC_REFLECT( zmqplugin::token::transfer,
            (from)(to)(quantity)(memo) )

FC_REFLECT( zmqplugin::token::issue,
            (to)(quantity)(memo) )

FC_REFLECT( zmqplugin::token::open,
            (owner)(symbol)(ram_payer) )

FC_REFLECT( zmqplugin::resource_balance,
            (account_name)(ram_quota)(ram_usage)(net_weight)(cpu_weight)(net_limit)(cpu_limit) )

FC_REFLECT( zmqplugin::currency_balance,
            (account_name)(contract)(balance)(stake)(refund)(deleted))

FC_REFLECT( zmqplugin::voter_info,
            (owner)(proxy)(producers)(staked)(last_vote_weight)(proxied_vote_weight)(is_proxy) )

FC_REFLECT( zmqplugin::zmq_action_object,
            (global_action_seq)(block_num)(block_time)(action_trace)
            (resource_balances)(voter_infos)(currency_balances)(last_irreversible_block) )

FC_REFLECT( zmqplugin::zmq_irreversible_block_object,
            (irreversible_block_num)(irreversible_block_digest) )

FC_REFLECT( zmqplugin::zmq_fork_block_object,
            (invalid_block_num) )

FC_REFLECT( zmqplugin::zmq_accepted_block_object,
            (accepted_block_num)(accepted_block_timestamp)(accepted_block_producer)(accepted_block_digest) )

FC_REFLECT( zmqplugin::zmq_failed_transaction_object,
            (trx_id)(block_num)(status_name)(status_int) )

FC_REFLECT( zmqplugin::zmq_accounts_info_object,
            (resource_balances)(voter_infos)(currency_balances))


FC_REFLECT( eosio::zmq_apis::read_only::token_params,
            (contract)(symbol) )
FC_REFLECT( eosio::zmq_apis::read_only::get_accounts_balance_params,
            (tokens) )
FC_REFLECT( eosio::zmq_apis::read_only::get_accounts_balance_result,
            (result) )

FC_REFLECT( eosio::zmq_apis::read_only::get_balance_by_account_params,
            (account)(tokens) )
FC_REFLECT( eosio::zmq_apis::read_only::get_balance_by_account_result,
            (result) )
