#include <infra-did-registry.hpp>

using namespace eosio;

namespace infra_did {

void infra_did_registry::accsetattr( const name& account, const string& key, const string& value ) {
   check( is_account(account), "account not exists" );
   check( key.size() > 0, "empty key" );

   require_auth( account );
   account_did_attr_table acc_did_attr_db( get_self(), get_self().value );
   auto itr = acc_did_attr_db.find( account.value );

   if ( itr == acc_did_attr_db.end() ) {
      acc_did_attr_db.emplace( account, [&]( account_did_attr& acc_did_attr ) {
         acc_did_attr.account = account;
         if (!value.empty()) {
            acc_did_attr.attr[key] = value;
         }
      });
   } else {
      acc_did_attr_db.modify( itr, same_payer, [&]( account_did_attr& acc_did_attr ) {
         if (!value.empty()) {
            acc_did_attr.attr[key] = value;
         } else {
            acc_did_attr.attr.erase(key);
         }
      });
   }
}

void infra_did_registry::accclearattr( const name& account ) {
   check( is_account(account), "account not exists" );

   require_auth( account );

   account_did_attr_table acc_did_attr_db( get_self(), get_self().value );
   auto itr = acc_did_attr_db.find( account.value );
   if ( itr != acc_did_attr_db.end() ) {
      acc_did_attr_db.erase(itr);
   }
}

void infra_did_registry::pksetattr( const public_key& pk, const string& key, const string& value, const signature& sig, const name& ram_payer ) {

   check(pk.index() <= 1, "not supported public key type" );
   check( key.size() > 0, "empty key" );

   pub_key_id_t pub_key_info = get_pub_key_id_info( pk );

   const checksum256 sig_digest = pksetattr_sig_digest( pk, pub_key_info.nonce, key, value );
   check_pk_did_signature( pub_key_info.pkid, pk, sig_digest, sig );

   pub_key_did_table pk_did_db( get_self(), get_self().value );

   if ( pub_key_info.pkid == 0 ) {
      require_auth( ram_payer );
      // create pk did entry
      uint64_t pkid = get_next_pkid();
      pk_did_db.emplace( ram_payer, [&]( pub_key_did& pk_did ) {
         pk_did.pkid = pkid;
         pk_did.pk = pk;
         pk_did.nonce = 1;
         if (!value.empty()) {
            pk_did.attr[key] = value;
         }
      });
   } else {
      auto itr = pk_did_db.find(pub_key_info.pkid);

      pk_did_db.modify( itr, same_payer, [&]( pub_key_did& pk_did ) {
         pk_did.nonce++;
         if (!value.empty()) {
            pk_did.attr[key] = value;
         } else {
            pk_did.attr.erase(key);
         }
      });
   }
}

void infra_did_registry::pkchowner( const public_key& pk, const public_key& new_owner_pk, const signature& sig, const name& ram_payer ) {

   check(pk.index() <= 1, "not supported public key type" );
   check(new_owner_pk.index() <= 1, "not supported public key type - new_owner_pk" );

   pub_key_id_t pub_key_info = get_pub_key_id_info( pk );

   const checksum256 sig_digest = pkchowner_sig_digest( pk, pub_key_info.nonce, new_owner_pk );
   check_pk_did_signature( pub_key_info.pkid, pk, sig_digest, sig );

   pub_key_did_table pk_did_db( get_self(), get_self().value );
   pub_key_did_owner_table pk_did_owner_db( get_self(), get_self().value );

   require_auth( ram_payer );

   if ( pub_key_info.pkid == 0 ) {
      uint64_t pkid = get_next_pkid();

      pk_did_db.emplace( ram_payer, [&]( pub_key_did& pk_did ) {
         pk_did.pkid = pkid;
         pk_did.pk = pk;
         pk_did.nonce = 1;
      });

      pk_did_owner_db.emplace( ram_payer, [&]( pub_key_did_owner& pk_did_owner ) {
         pk_did_owner.pkid = pkid;
         pk_did_owner.owner_pk = new_owner_pk;
      });
   } else {
      auto itr = pk_did_db.find(pub_key_info.pkid);

      pk_did_db.modify( itr, same_payer, [&]( pub_key_did& pk_did ) {
         pk_did.nonce++;
      });

      auto itr_pk_did_owner = pk_did_owner_db.find(pub_key_info.pkid);
      if ( itr_pk_did_owner == pk_did_owner_db.end() ) {
         pk_did_owner_db.emplace( ram_payer, [&]( pub_key_did_owner& pk_did_owner ) {
            pk_did_owner.pkid = pub_key_info.pkid;
            pk_did_owner.owner_pk = new_owner_pk;
         });
      } else {
         pk_did_owner_db.modify( itr_pk_did_owner, same_payer, [&]( pub_key_did_owner& pk_did_owner ) {
            pk_did_owner.owner_pk = new_owner_pk;
         });
      }
   }
}

void infra_did_registry::pkdidclear( const public_key& pk, const signature& sig ) {

   check(pk.index() <= 1, "not supported public key type" );

   pub_key_id_t pub_key_info = get_pub_key_id_info( pk );

   const checksum256 sig_digest = pkdidclear_sig_digest( pk, pub_key_info.nonce );
   check_pk_did_signature( pub_key_info.pkid, pk, sig_digest, sig );

   if ( pub_key_info.pkid > 0 ) {
      pub_key_did_table pk_did_db( get_self(), get_self().value );
      auto itr_pk_did = pk_did_db.find(pub_key_info.pkid);
      if ( itr_pk_did != pk_did_db.end() ) {
         pk_did_db.erase(itr_pk_did);
      }

      pub_key_did_owner_table pk_did_owner_db( get_self(), get_self().value );
      auto itr_pk_did_owner = pk_did_owner_db.find(pub_key_info.pkid);
      if ( itr_pk_did_owner != pk_did_owner_db.end() ) {
         pk_did_owner_db.erase(itr_pk_did_owner);
      }
   }
}

infra_did_registry::pub_key_id_t infra_did_registry::get_pub_key_id_info( const public_key& pk ) {
   pub_key_did_table pk_did_db( get_self(), get_self().value );
   auto pk_index = pk_did_db.get_index<"bypk"_n>();
   auto itr_pk_idx = pk_index.lower_bound(get_pubkey_index_value(pk));

   if ( itr_pk_idx != pk_index.end() && itr_pk_idx->pk == pk ) {
      return pub_key_id_t{ itr_pk_idx->pkid, itr_pk_idx->nonce };
   } else {
      return pub_key_id_t{ 0, 0 };
   }
}

checksum256 infra_did_registry::pksetattr_sig_digest( const public_key& pk, const uint16_t nonce, const string& key, const string& value ) {
   string prefix;
   prefix.append(INFRA_DID_PUB_KEY_DID_SIGN_DATA_PREFIX);
   prefix.append("pksetattr");
   size_t signed_data_size = prefix.size() + pack_size(pk) + 2 + key.size() + value.size();
   std::vector<char> signed_data;
   signed_data.resize(signed_data_size);

   datastream<char*> ds( signed_data.data(), signed_data.size() );
   ds.write(prefix.c_str(), prefix.size());
   ds << pk;
   ds << nonce;
   ds.write(key.c_str(), key.size());
   ds.write(value.c_str(), value.size());

   return sha256(signed_data.data(), signed_data_size);
}

checksum256 infra_did_registry::pkchowner_sig_digest( const public_key& pk, const uint16_t nonce, const public_key& new_owner_pk ) {
   string prefix;
   prefix.append(INFRA_DID_PUB_KEY_DID_SIGN_DATA_PREFIX);
   prefix.append("pkchowner" );
   size_t signed_data_size = prefix.size() + pack_size(pk) + 2 + pack_size(new_owner_pk);
   std::vector<char> signed_data;
   signed_data.resize(signed_data_size);

   datastream<char*> ds( signed_data.data(), signed_data.size() );
   ds.write(prefix.c_str(), prefix.size());
   ds << pk;
   ds << nonce;
   ds << new_owner_pk;

   return sha256(signed_data.data(), signed_data_size);
}

checksum256 infra_did_registry::pkdidclear_sig_digest( const public_key& pk, const uint16_t nonce ) {
   string prefix;
   prefix.append(INFRA_DID_PUB_KEY_DID_SIGN_DATA_PREFIX);
   prefix.append("pkdidclear" );
   size_t signed_data_size = prefix.size() + pack_size(pk) + 2;
   std::vector<char> signed_data;
   signed_data.resize(signed_data_size);

   datastream<char*> ds( signed_data.data(), signed_data.size() );
   ds.write(prefix.c_str(), prefix.size());
   ds << pk;
   ds << nonce;

   return sha256(signed_data.data(), signed_data_size);
}

void infra_did_registry::check_pk_did_signature( const uint64_t pkid, const public_key& pk, const checksum256& digest, const signature& sig ) {

   if ( pkid > 0 ) {
      pub_key_did_owner_table pk_did_owner_db(get_self(), get_self().value );
      auto itr = pk_did_owner_db.find( pkid );
      if ( itr != pk_did_owner_db.end() ) {
         assert_recover_key(digest, sig, itr->owner_pk);
         return;
      }
   }

   assert_recover_key(digest, sig, pk);
}

uint64_t infra_did_registry::get_next_pkid() {
   global_state_singleton global(get_self(), get_self().value);
   uint64_t next_id = 1;

   if (global.exists()) {
      global_state state = global.get();
      next_id = state.next_pkid;
      state.next_pkid++;
      global.set( state, get_self() );
   } else {
      global_state state;
      state.next_pkid = 2;
      global.set( state, get_self() );
   }

   return next_id;
}

} /// namespace infra_did
