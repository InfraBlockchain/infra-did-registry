#pragma once

#include <eosio/eosio.hpp>
#include <eosio/crypto.hpp>
#include <eosio/singleton.hpp>

#include <string>

#define INFRA_DID_PUB_KEY_DID_SIGN_DATA_PREFIX "infra-mainnet"
#define INFRA_DID_NONCE_VALUE_FOR_REVOKED_PUB_KEY_DID 65535

using namespace eosio;

namespace infra_did {

   using std::string;

   /**
    * InfraBlockchain DID Registry Contract
    */
   class [[eosio::contract("infra-did-registry")]] infra_did_registry: public contract {
      public:
         using contract::contract;

         /**
          * [Account DID] set attribute for a DID
          *
          * @param account
          * @param key
          * @param value
          */
         [[eosio::action]]
         void accsetattr( const name& account, const string& key, const string& value );

         /**
          * [Account DID] clear attributes for a DID
          *
          * @param account
          */
         [[eosio::action]]
         void accclearattr( const name& account );

         /**
          * [Account DID] register did as trusted
          *
          * @param authorizer
          * @param account
          * @param properties
          */
         [[eosio::action]]
         void acctrstdreg(const name& authorizer, const name& account, const string& properties);

         /**
          * [Account DID] update properties of trusted did
          *
          * @param authorizer
          * @param account
          * @param properties
          */
         [[eosio::action]]
         void acctrstdupdt(const name& authorizer, const name& account, const string& properties);

         /**
          * [Account DID] deregister did as trusted
          *
          * @param authorizer
          * @param account
          */
         [[eosio::action]]
         void acctrstdrmv(const name& authorizer, const name& account);

         /**
          * [Public Key DID] set attribute for a DID
          *
          * @param pk
          * @param key
          * @param value
          * @param sig
          * @param ram_payer
          */
         [[eosio::action]]
         void pksetattr( const public_key& pk, const string& key, const string& value, const signature& sig, const name& ram_payer );

         /**
          * [Public Key DID] change owner
          *
          * @param pk
          * @param new_owner_pk
          * @param sig
          * @param ram_payer
          */
         [[eosio::action]]
         void pkchowner( const public_key& pk, const public_key& new_owner_pk, const signature& sig, const name& ram_payer );

         /**
          * [Public Key DID] revoke did
          * @param pk
          * @param sig
          * @param ram_payer
          */
         [[eosio::action]]
         void pkdidrevoke( const public_key& pk, const signature& sig, const name& ram_payer );

         /**
          * [Public Key DID] clear did data
          *
          * @param pk
          * @param sig
          */
         [[eosio::action]]
         void pkdidclear( const public_key& pk, const signature& sig );

         /**
          * [Public Key DID] remove revoked did data
          *
          * @param pkid
          */
         [[eosio::action]]
         void pkdidrmvrvkd( const uint64_t pkid );

         /**
          * [Public Key DID] register did as trusted
          *
          * @param authorizer
          * @param pk
          * @param properties
          */
         [[eosio::action]]
         void pktrstdreg(const name& authorizer, const public_key& pk, const string& properties);

         /**
          * [Public Key DID] update properties of trusted did
          *
          * @param authorizer
          * @param pk
          * @param properties
          */
         [[eosio::action]]
         void pktrstdupdt(const name& authorizer, const public_key& pk, const string& properties);

         /**
          * [Public Key DID] deregister did as trusted
          *
          * @param authorizer
          * @param pk
          */
         [[eosio::action]]
         void pktrstdrmv(const name& authorizer, const public_key& pk);

      private:

         checksum256 pksetattr_sig_digest( const public_key& pk, const uint16_t nonce, const string& key, const string& value );
         checksum256 pkchowner_sig_digest( const public_key& pk, const uint16_t nonce, const public_key& new_owner_pk );
         checksum256 pkdidclear_sig_digest( const public_key& pk, const uint16_t nonce );
         checksum256 pkdidrevoke_sig_digest( const public_key& pk, const uint16_t nonce );

         void check_pk_did_signature( const uint64_t pkid, const public_key& pk, const checksum256& digest, const signature& sig );

         // saving DID-related attributes (optional) for the DIDs using chain account
         // if there is no account_did entry matching a chain account, DIDDoc is composed using only chain account info.
         struct [[eosio::table]] account_did_attr {
            name  account;
            std::map<std::string, std::string> attr;

            uint64_t primary_key() const { return account.value; }
         };

         typedef eosio::multi_index< "accdidattr"_n, account_did_attr > account_did_attr_table;

         struct [[eosio::table]] pub_key_did {
            uint64_t   pkid; // public key id
            public_key pk; // only supports ecc_public_key(secp256k1, secp256r1) (33 bytes compressed key format)
            uint16_t   nonce; // allows upto 65535 update transactions per a pub-key did. to revoke pub-key did, did owner should set nonce value as 65535
            std::map<string, string> attr;

            uint64_t primary_key() const { return pkid; }
            checksum256 by_pk() const { return get_pubkey_index_value(pk); /*get_pubkey_hash(pk);*/ } // secondary index for public key

            EOSLIB_SERIALIZE(pub_key_did, (pkid)(pk)(nonce)(attr))
         };

         typedef eosio::multi_index<"pubkeydid"_n,
            pub_key_did,
            indexed_by<"bypk"_n, const_mem_fun<pub_key_did, checksum256, &pub_key_did::by_pk>>
         > pub_key_did_table;

         struct pub_key_id_t {
            uint64_t pkid;
            uint16_t nonce;
         };

         pub_key_id_t get_pub_key_id_info( const public_key& pk );

         // if there is pub_key_did_owner entry matching with a pub_key_did entry,
         // the owner of the pub_key_did is pub_key_did_owner.owner_pk, not pub_key_did.pk
         struct [[eosio::table]] pub_key_did_owner {
            uint64_t   pkid; // public key id
            public_key owner_pk; // only support ecc_public_key (33 bytes compressed key format)

            uint64_t primary_key() const { return pkid; }

            EOSLIB_SERIALIZE( pub_key_did_owner, (pkid)(owner_pk) )
         };

         typedef eosio::multi_index< "pkdidowner"_n, pub_key_did_owner > pub_key_did_owner_table;

         // trusted account can add trusted DID in trusted_pub_key_did table with scope as contract account name
         struct [[eosio::table]] trusted_pub_key_did {
            uint64_t id; // unique identifier
            name authorizer; // trusted account name
            public_key pk;  // only supports ecc_public_key(secp256k1, secp256r1) (33 bytes compressed key format)
            string properties; // properties for the DID, stringified JSON
            
            uint64_t primary_key() const { return id; }
            uint64_t by_authorizer() const { return authorizer.value; } // secondary index for trusted account
            checksum256 by_pk() const { return get_pubkey_index_value(pk); } // secondary index for public key
            checksum256 by_authpk() const { return get_auth_pk_index_value(authorizer, pk); } // secondary index for authorizer and public key

            EOSLIB_SERIALIZE( trusted_pub_key_did, (id)(authorizer)(pk)(properties) )
         };

         typedef eosio::multi_index< "trstdpkdid"_n, 
            trusted_pub_key_did,
            indexed_by<"byauthorizer"_n, const_mem_fun<trusted_pub_key_did, uint64_t, &trusted_pub_key_did::by_authorizer>>,
            indexed_by<"bypk"_n, const_mem_fun<trusted_pub_key_did, checksum256, &trusted_pub_key_did::by_pk>>,
            indexed_by<"byauthpk"_n, const_mem_fun<trusted_pub_key_did, checksum256, &trusted_pub_key_did::by_authpk>>
         > trusted_pub_key_did_table;

         // trusted account can add trusted DID in trusted_account_did table with scope as contract account name
         struct [[eosio::table]] trusted_account_did {
            uint64_t id; // unique identifier
            name authorizer; // trusted account name
            name account; // trusted account name
            string properties; // properties for the DID, stringified JSON
            
            uint64_t primary_key() const { return id; }
            uint64_t by_authorizer() const { return authorizer.value; } // secondary index for trusted account
            uint64_t by_account() const { return account.value; } // secondary index for account
            uint128_t by_authacc() const { return get_auth_acc_index_value(authorizer, account); } // secondary index for authorizer and account

            EOSLIB_SERIALIZE( trusted_account_did, (id)(authorizer)(account)(properties) )
         }; 

         typedef eosio::multi_index< "trstdaccdid"_n, 
            trusted_account_did,
            indexed_by<"byauthorizer"_n, const_mem_fun<trusted_account_did, uint64_t, &trusted_account_did::by_authorizer>>,
            indexed_by<"byaccount"_n, const_mem_fun<trusted_account_did, uint64_t, &trusted_account_did::by_account>>,
            indexed_by<"byauthacc"_n, const_mem_fun<trusted_account_did, uint128_t, &trusted_account_did::by_authacc>>
         > trusted_account_did_table;

         struct [[eosio::table("global")]] global_state {
            global_state() { }
            uint64_t next_pkid;

            EOSLIB_SERIALIZE( global_state, (next_pkid) )
         };

         typedef eosio::singleton< "global"_n, global_state > global_state_singleton;

         uint64_t get_next_pkid();

//         static checksum256 get_pubkey_hash(const public_key &pk) {
//            size_t var_i = pk.index();
//            // only support ecc_public_key (33 bytes compressed key format)
//            check(var_i <= 1, "not supported public_key type");
//
//            auto& ecc_pk = var_i == 0 ? std::get<0>(pk) : std::get<1>(pk); // secp256k1 or secp256r1
//
//            std::array<char, 34> buf;
//            buf[0] = var_i;
//            std::copy(std::begin(ecc_pk), std::end(ecc_pk), std::begin(buf)+1);
//
//            return sha256(buf.begin(), 34);
//         }

         static checksum256 get_pubkey_index_value(const public_key &pk) {
            size_t var_idx = pk.index();
            // only support ecc_public_key (33 bytes compressed key format)
            check(var_idx <= 1, "not supported public_key type");

            auto& ecc_pk = var_idx == 0 ? std::get<0>(pk) : std::get<1>(pk); // secp256k1 or secp256r1

            std::array<unsigned char, 32> buf;
            //buf[0] = var_i;
            std::copy(std::begin(ecc_pk)+1, std::end(ecc_pk), std::begin(buf));

            return checksum256(buf);
         }

         static uint128_t get_auth_acc_index_value(const name &authorizer, const name &account) {
            const uint64_t authorizer_value = authorizer.value;
            const uint64_t account_value = account.value;
            return (uint128_t(authorizer_value) << 64) | account_value;
         }

         static checksum256 get_auth_pk_index_value(const name &authorizer, const public_key &pk) {
            const uint64_t authorizer_value = authorizer.value;
            unsigned char authorizer_char_arr[sizeof(authorizer_value)];
            std::memcpy(authorizer_char_arr,&authorizer_value,sizeof(authorizer_value));

            size_t var_idx = pk.index();
            // only support ecc_public_key (33 bytes compressed key format)
            check(var_idx <= 1, "not supported public_key type");

            auto& ecc_pk = var_idx == 0 ? std::get<0>(pk) : std::get<1>(pk); // secp256k1 or secp256r1

            std::array<unsigned char, 32> buf;
            //buf[0] = var_i;
            std::copy(std::begin(authorizer_char_arr), std::end(authorizer_char_arr), std::begin(buf));
            std::copy(std::begin(ecc_pk)+9, std::end(ecc_pk), std::begin(buf)+8);
            return checksum256(buf);
         }
   };

}