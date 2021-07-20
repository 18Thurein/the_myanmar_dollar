#include <nano/crypto_lib/random_pool.hpp>
#include <nano/lib/config.hpp>
#include <nano/lib/numbers.hpp>
#include <nano/secure/blockstore.hpp>
#include <nano/secure/common.hpp>

#include <crypto/cryptopp/words.h>

#include <boost/endian/conversion.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/variant/get.hpp>

#include <limits>
#include <queue>

#include <crypto/ed25519-donna/ed25519.h>

size_t constexpr nano::send_block::size;
size_t constexpr nano::receive_block::size;
size_t constexpr nano::open_block::size;
size_t constexpr nano::change_block::size;
size_t constexpr nano::state_block::size;

nano::nano_networks nano::network_constants::active_network = nano::nano_networks::ACTIVE_NETWORK;

namespace
{
char const * dev_private_key_data = "9353027BB40DC73D06D09DA1C57337AD337E35846B1CA1DD62B35D3197D294E7";
char const * dev_public_key_data = "2AAB602339EF8124456E99448AC9833C9FFCEABB5C6D5FC8153ED4EEEEB06C01"; // myd_1code1jmmuw36j4px8c6jd6r8h6zzmodpq5fdz63chpnxuqd1u13bzm13x3k
char const * beta_public_key_data = "259A4037D18664264170687BDECCB70F9C3ADAB88FE18AA1554B01EFA929C63E"; // myd_1beta1ux53m66s1q1t5uuu8dg5ww9dfdj5z3jciockr3xynkmjjyyk6tyam8
char const * live_public_key_data = "5B109B017848B8761048D374BC9338FC302DD102A505E9C2DD281BDB6A9607C5"; // myd_1prime1qik7rgra6jnunqkbmjz3i7qai7ba7x93ftc1uufobe3y7bnjjzif1
std::string const test_public_key_data = nano::get_env_or_default ("myd_TEST_GENESIS_PUB", "6999D003227E95192E3997D9B09D19ECE634F143CA7D60CB6C63476295410881"); // myd_1test13k6zno56q5m7ysp4gjmu988mrn9kmxe57prrt9eccn4463471m18w9
char const * dev_genesis_data = R"%%%({
	"type": "open",
	"source": "2AAB602339EF8124456E99448AC9833C9FFCEABB5C6D5FC8153ED4EEEEB06C01",
	"representative": "myd_1code1jmmuw36j4px8c6jd6r8h6zzmodpq5fdz63chpnxuqd1u13bzm13x3k",
	"account": "myd_1code1jmmuw36j4px8c6jd6r8h6zzmodpq5fdz63chpnxuqd1u13bzm13x3k",
	"work": "4c1f954b51d662a8",
	"signature": "94A6F282205B534F8B7D275DB668156230A5653A35085D3D93F62E4021219B93032563749C2FBEB7FE522B0F1494D15860F12D73E71942215536B268CC227207"
	})%%%";

char const * beta_genesis_data = R"%%%({
	"type": "open",
	"source": "259A4037D18664264170687BDECCB70F9C3ADAB88FE18AA1554B01EFA929C63E",
	"representative": "myd_1beta1ux53m66s1q1t5uuu8dg5ww9dfdj5z3jciockr3xynkmjjyyk6tyam8",
	"account": "myd_1beta1ux53m66s1q1t5uuu8dg5ww9dfdj5z3jciockr3xynkmjjyyk6tyam8",
	"work": "8dbb193f0788cdd2",
	"signature": "96C890650FFCC8DFBA9A45694583E74C07255C2AF7B991D12B8B5AAA3CF178753FC3F806C45FDFB25E76A3AE3A55A6943D5AE61817BADA311B81FD6DE78C0C08"
	})%%%";

char const * live_genesis_data = R"%%%({
	"type": "open",
	"source": "5B109B017848B8761048D374BC9338FC302DD102A505E9C2DD281BDB6A9607C5",
	"representative": "myd_1prime1qik7rgra6jnunqkbmjz3i7qai7ba7x93ftc1uufobe3y7bnjjzif1",
	"account": "myd_1prime1qik7rgra6jnunqkbmjz3i7qai7ba7x93ftc1uufobe3y7bnjjzif1",
	"work": "4dbd4542c5bd1608",
	"signature": "48A91C74DB922D1F9E88568A3B0311FE450F3B07CA273634203CC56BF2225FED9F001008292279BF6F5C1541446A9B4C20CA3AFA03625EF0D385994C1D13C70B"
	})%%%";

std::string const test_genesis_data = nano::get_env_or_default ("myd_TEST_GENESIS_BLOCK", R"%%%({
	"type": "open",
	"source": "6999D003227E95192E3997D9B09D19ECE634F143CA7D60CB6C63476295410881",
	"representative": "myd_1test13k6zno56q5m7ysp4gjmu988mrn9kmxe57prrt9eccn4463471m18w9",
	"account": "myd_1test13k6zno56q5m7ysp4gjmu988mrn9kmxe57prrt9eccn4463471m18w9",
	"work": "bd090fff54f59a98",
	"signature": "16CED9B7F6E86527812FD52F3DF2E2D9D18D6A8423278FEFFAA55A6886FE62C6878EC767982650DB7FC42AA7D493A38DD8292C935CED24A799DF1A2952627800"
	})%%%");

std::shared_ptr<nano::block> parse_block_from_genesis_data (std::string const & genesis_data_a)
{
	boost::property_tree::ptree tree;
	std::stringstream istream (genesis_data_a);
	boost::property_tree::read_json (istream, tree);
	return nano::deserialize_block_json (tree);
}

char const * beta_canary_public_key_data = "868C6A9F79D4506E029B378262B91538C5CB26D7C346B63902FFEB365F1C1947"; // myd_33nefchqmo4ifr3bpfw4ecwjcg87semfhit8prwi7zzd8shjr8c9qdxeqmnx
char const * live_canary_public_key_data = "7CBAF192A3763DAEC9F9BAC1B2CDF665D8369F8400B4BC5AB4BA31C00BAA4404"; // myd_1z7ty8bc8xjxou6zmgp3pd8zesgr8thra17nqjfdbgjjr17tnj16fjntfqfn
std::string const test_canary_public_key_data = nano::get_env_or_default ("myd_TEST_CANARY_PUB", "3BAD2C554ACE05F5E528FBBCE79D51E552C55FA765CCFD89B289C4835DE5F04A"); // myd_1gxf7jcnomi7yqkkjyxwwygo5sckrohtgsgezp6u74g6ifgydw4cajwbk8bf
}

nano::network_params::network_params () :
	network_params (network_constants::active_network)
{
}

nano::network_params::network_params (nano::nano_networks network_a) :
	network (network_a), ledger (network), voting (network), node (network), portmapping (network), bootstrap (network)
{
	unsigned constexpr kdf_full_work = 64 * 1024;
	unsigned constexpr kdf_dev_work = 8;
	kdf_work = network.is_dev_network () ? kdf_dev_work : kdf_full_work;
	header_magic_number = network.is_dev_network () ? std::array<uint8_t, 2>{ { 'M', 'A' } } : network.is_beta_network () ? std::array<uint8_t, 2>{ { 'M', 'B' } } : network.is_live_network () ? std::array<uint8_t, 2>{ { 'M', 'C' } } : nano::test_magic_number ();
}

uint8_t nano::protocol_constants::protocol_version_min () const
{
	return protocol_version_min_m;
}

nano::ledger_constants::ledger_constants (nano::network_constants & network_constants) :
	ledger_constants (network_constants.network ())
{
}

nano::ledger_constants::ledger_constants (nano::nano_networks network_a) :
	zero_key ("0"),
	dev_genesis_key (dev_private_key_data),
	nano_dev_account (dev_public_key_data),
	nano_beta_account (beta_public_key_data),
	nano_live_account (live_public_key_data),
	nano_test_account (test_public_key_data),
	nano_dev_genesis (dev_genesis_data),
	nano_beta_genesis (beta_genesis_data),
	nano_live_genesis (live_genesis_data),
	nano_test_genesis (test_genesis_data),
	genesis_account (network_a == nano::nano_networks::nano_dev_network ? nano_dev_account : network_a == nano::nano_networks::nano_beta_network ? nano_beta_account : network_a == nano::nano_networks::nano_test_network ? nano_test_account : nano_live_account),
	genesis_block (network_a == nano::nano_networks::nano_dev_network ? nano_dev_genesis : network_a == nano::nano_networks::nano_beta_network ? nano_beta_genesis : network_a == nano::nano_networks::nano_test_network ? nano_test_genesis : nano_live_genesis),
	genesis_hash (parse_block_from_genesis_data (genesis_block)->hash ()),
	genesis_amount (std::numeric_limits<nano::uint128_t>::max ()),
	burn_account (0),
	nano_dev_final_votes_canary_account (dev_public_key_data),
	nano_beta_final_votes_canary_account (beta_canary_public_key_data),
	nano_live_final_votes_canary_account (live_canary_public_key_data),
	nano_test_final_votes_canary_account (test_canary_public_key_data),
	final_votes_canary_account (network_a == nano::nano_networks::nano_dev_network ? nano_dev_final_votes_canary_account : network_a == nano::nano_networks::nano_beta_network ? nano_beta_final_votes_canary_account : network_a == nano::nano_networks::nano_test_network ? nano_test_final_votes_canary_account : nano_live_final_votes_canary_account),
	nano_dev_final_votes_canary_height (1),
	nano_beta_final_votes_canary_height (1),
	nano_live_final_votes_canary_height (1),
	nano_test_final_votes_canary_height (1),
	final_votes_canary_height (network_a == nano::nano_networks::nano_dev_network ? nano_dev_final_votes_canary_height : network_a == nano::nano_networks::nano_beta_network ? nano_beta_final_votes_canary_height : network_a == nano::nano_networks::nano_test_network ? nano_test_final_votes_canary_height : nano_live_final_votes_canary_height)
{
	nano::link epoch_link_v1;
	const char * epoch_message_v1 ("epoch v1 block");
	strncpy ((char *)epoch_link_v1.bytes.data (), epoch_message_v1, epoch_link_v1.bytes.size ());
	epochs.add (nano::epoch::epoch_1, genesis_account, epoch_link_v1);

	nano::link epoch_link_v2;
	nano::account nano_live_epoch_v2_signer;
	auto error (nano_live_epoch_v2_signer.decode_account ("myd_3qb6o6i1tkzr6jwr5s7eehfxwg9x6eemitdinbpi7u8bjjwsgqfj4wzser3x"));
	debug_assert (!error);
	auto epoch_v2_signer (network_a == nano::nano_networks::nano_dev_network ? nano_dev_account : network_a == nano::nano_networks::nano_beta_network ? nano_beta_account : network_a == nano::nano_networks::nano_test_network ? nano_test_account : nano_live_epoch_v2_signer);
	const char * epoch_message_v2 ("epoch v2 block");
	strncpy ((char *)epoch_link_v2.bytes.data (), epoch_message_v2, epoch_link_v2.bytes.size ());
	epochs.add (nano::epoch::epoch_2, epoch_v2_signer, epoch_link_v2);
}

nano::random_constants::random_constants ()
{
	nano::random_pool::generate_block (not_an_account.bytes.data (), not_an_account.bytes.size ());
	nano::random_pool::generate_block (random_128.bytes.data (), random_128.bytes.size ());
}

nano::node_constants::node_constants (nano::network_constants & network_constants)
{
	period = network_constants.is_dev_network () ? std::chrono::seconds (1) : std::chrono::seconds (60);
	half_period = network_constants.is_dev_network () ? std::chrono::milliseconds (500) : std::chrono::milliseconds (30 * 1000);
	idle_timeout = network_constants.is_dev_network () ? period * 15 : period * 2;
	cutoff = period * 5;
	syn_cookie_cutoff = std::chrono::seconds (5);
	backup_interval = std::chrono::minutes (5);
	bootstrap_interval = std::chrono::seconds (15 * 60);
	search_pending_interval = network_constants.is_dev_network () ? std::chrono::seconds (1) : std::chrono::seconds (5 * 60);
	peer_interval = search_pending_interval;
	unchecked_cleaning_interval = std::chrono::minutes (30);
	process_confirmed_interval = network_constants.is_dev_network () ? std::chrono::milliseconds (50) : std::chrono::milliseconds (500);
	max_peers_per_ip = network_constants.is_dev_network () ? 10 : 5;
	max_peers_per_subnetwork = max_peers_per_ip * 4;
	max_weight_samples = (network_constants.is_live_network () || network_constants.is_test_network ()) ? 4032 : 288;
	weight_period = 5 * 60; // 5 minutes
}

nano::voting_constants::voting_constants (nano::network_constants & network_constants) :
	max_cache{ network_constants.is_dev_network () ? 256U : 128U * 1024 },
	delay{ network_constants.is_dev_network () ? 1 : 15 }
{
}

nano::portmapping_constants::portmapping_constants (nano::network_constants & network_constants)
{
	lease_duration = std::chrono::seconds (1787); // ~30 minutes
	health_check_period = std::chrono::seconds (53);
}

nano::bootstrap_constants::bootstrap_constants (nano::network_constants & network_constants)
{
	lazy_max_pull_blocks = network_constants.is_dev_network () ? 2 : 512;
	lazy_min_pull_blocks = network_constants.is_dev_network () ? 1 : 32;
	frontier_retry_limit = network_constants.is_dev_network () ? 2 : 16;
	lazy_retry_limit = network_constants.is_dev_network () ? 2 : frontier_retry_limit * 4;
	lazy_destinations_retry_limit = network_constants.is_dev_network () ? 1 : frontier_retry_limit / 4;
	gap_cache_bootstrap_start_interval = network_constants.is_dev_network () ? std::chrono::milliseconds (5) : std::chrono::milliseconds (30 * 1000);
	default_frontiers_age_seconds = network_constants.is_dev_network () ? 1 : 24 * 60 * 60; // 1 second for dev network, 24 hours for live/beta
}

// Create a new random keypair
nano::keypair::keypair ()
{
	random_pool::generate_block (prv.bytes.data (), prv.bytes.size ());
	ed25519_publickey (prv.bytes.data (), pub.bytes.data ());
}

// Create a keypair given a private key
nano::keypair::keypair (nano::raw_key && prv_a) :
	prv (std::move (prv_a))
{
	ed25519_publickey (prv.bytes.data (), pub.bytes.data ());
}

// Create a keypair given a hex string of the private key
nano::keypair::keypair (std::string const & prv_a)
{
	[[maybe_unused]] auto error (prv.decode_hex (prv_a));
	debug_assert (!error);
	ed25519_publickey (prv.bytes.data (), pub.bytes.data ());
}

// Serialize a block prefixed with an 8-bit typecode
void nano::serialize_block (nano::stream & stream_a, nano::block const & block_a)
{
	write (stream_a, block_a.type ());
	block_a.serialize (stream_a);
}

nano::account_info::account_info (nano::block_hash const & head_a, nano::account const & representative_a, nano::block_hash const & open_block_a, nano::amount const & balance_a, uint64_t modified_a, uint64_t block_count_a, nano::epoch epoch_a) :
	head (head_a),
	representative (representative_a),
	open_block (open_block_a),
	balance (balance_a),
	modified (modified_a),
	block_count (block_count_a),
	epoch_m (epoch_a)
{
}

bool nano::account_info::deserialize (nano::stream & stream_a)
{
	auto error (false);
	try
	{
		nano::read (stream_a, head.bytes);
		nano::read (stream_a, representative.bytes);
		nano::read (stream_a, open_block.bytes);
		nano::read (stream_a, balance.bytes);
		nano::read (stream_a, modified);
		nano::read (stream_a, block_count);
		nano::read (stream_a, epoch_m);
	}
	catch (std::runtime_error const &)
	{
		error = true;
	}

	return error;
}

bool nano::account_info::operator== (nano::account_info const & other_a) const
{
	return head == other_a.head && representative == other_a.representative && open_block == other_a.open_block && balance == other_a.balance && modified == other_a.modified && block_count == other_a.block_count && epoch () == other_a.epoch ();
}

bool nano::account_info::operator!= (nano::account_info const & other_a) const
{
	return !(*this == other_a);
}

size_t nano::account_info::db_size () const
{
	debug_assert (reinterpret_cast<const uint8_t *> (this) == reinterpret_cast<const uint8_t *> (&head));
	debug_assert (reinterpret_cast<const uint8_t *> (&head) + sizeof (head) == reinterpret_cast<const uint8_t *> (&representative));
	debug_assert (reinterpret_cast<const uint8_t *> (&representative) + sizeof (representative) == reinterpret_cast<const uint8_t *> (&open_block));
	debug_assert (reinterpret_cast<const uint8_t *> (&open_block) + sizeof (open_block) == reinterpret_cast<const uint8_t *> (&balance));
	debug_assert (reinterpret_cast<const uint8_t *> (&balance) + sizeof (balance) == reinterpret_cast<const uint8_t *> (&modified));
	debug_assert (reinterpret_cast<const uint8_t *> (&modified) + sizeof (modified) == reinterpret_cast<const uint8_t *> (&block_count));
	debug_assert (reinterpret_cast<const uint8_t *> (&block_count) + sizeof (block_count) == reinterpret_cast<const uint8_t *> (&epoch_m));
	return sizeof (head) + sizeof (representative) + sizeof (open_block) + sizeof (balance) + sizeof (modified) + sizeof (block_count) + sizeof (epoch_m);
}

nano::epoch nano::account_info::epoch () const
{
	return epoch_m;
}

nano::pending_info::pending_info (nano::account const & source_a, nano::amount const & amount_a, nano::epoch epoch_a) :
	source (source_a),
	amount (amount_a),
	epoch (epoch_a)
{
}

bool nano::pending_info::deserialize (nano::stream & stream_a)
{
	auto error (false);
	try
	{
		nano::read (stream_a, source.bytes);
		nano::read (stream_a, amount.bytes);
		nano::read (stream_a, epoch);
	}
	catch (std::runtime_error const &)
	{
		error = true;
	}

	return error;
}

size_t nano::pending_info::db_size () const
{
	return sizeof (source) + sizeof (amount) + sizeof (epoch);
}

bool nano::pending_info::operator== (nano::pending_info const & other_a) const
{
	return source == other_a.source && amount == other_a.amount && epoch == other_a.epoch;
}

nano::pending_key::pending_key (nano::account const & account_a, nano::block_hash const & hash_a) :
	account (account_a),
	hash (hash_a)
{
}

bool nano::pending_key::deserialize (nano::stream & stream_a)
{
	auto error (false);
	try
	{
		nano::read (stream_a, account.bytes);
		nano::read (stream_a, hash.bytes);
	}
	catch (std::runtime_error const &)
	{
		error = true;
	}

	return error;
}

bool nano::pending_key::operator== (nano::pending_key const & other_a) const
{
	return account == other_a.account && hash == other_a.hash;
}

nano::account const & nano::pending_key::key () const
{
	return account;
}

nano::unchecked_info::unchecked_info (std::shared_ptr<nano::block> const & block_a, nano::account const & account_a, uint64_t modified_a, nano::signature_verification verified_a, bool confirmed_a) :
	block (block_a),
	account (account_a),
	modified (modified_a),
	verified (verified_a),
	confirmed (confirmed_a)
{
}

void nano::unchecked_info::serialize (nano::stream & stream_a) const
{
	debug_assert (block != nullptr);
	nano::serialize_block (stream_a, *block);
	nano::write (stream_a, account.bytes);
	nano::write (stream_a, modified);
	nano::write (stream_a, verified);
}

bool nano::unchecked_info::deserialize (nano::stream & stream_a)
{
	block = nano::deserialize_block (stream_a);
	bool error (block == nullptr);
	if (!error)
	{
		try
		{
			nano::read (stream_a, account.bytes);
			nano::read (stream_a, modified);
			nano::read (stream_a, verified);
		}
		catch (std::runtime_error const &)
		{
			error = true;
		}
	}
	return error;
}

nano::endpoint_key::endpoint_key (const std::array<uint8_t, 16> & address_a, uint16_t port_a) :
	address (address_a), network_port (boost::endian::native_to_big (port_a))
{
}

const std::array<uint8_t, 16> & nano::endpoint_key::address_bytes () const
{
	return address;
}

uint16_t nano::endpoint_key::port () const
{
	return boost::endian::big_to_native (network_port);
}

nano::confirmation_height_info::confirmation_height_info (uint64_t confirmation_height_a, nano::block_hash const & confirmed_frontier_a) :
	height (confirmation_height_a),
	frontier (confirmed_frontier_a)
{
}

void nano::confirmation_height_info::serialize (nano::stream & stream_a) const
{
	nano::write (stream_a, height);
	nano::write (stream_a, frontier);
}

bool nano::confirmation_height_info::deserialize (nano::stream & stream_a)
{
	auto error (false);
	try
	{
		nano::read (stream_a, height);
		nano::read (stream_a, frontier);
	}
	catch (std::runtime_error const &)
	{
		error = true;
	}
	return error;
}

nano::block_info::block_info (nano::account const & account_a, nano::amount const & balance_a) :
	account (account_a),
	balance (balance_a)
{
}

bool nano::vote::operator== (nano::vote const & other_a) const
{
	auto blocks_equal (true);
	if (blocks.size () != other_a.blocks.size ())
	{
		blocks_equal = false;
	}
	else
	{
		for (auto i (0); blocks_equal && i < blocks.size (); ++i)
		{
			auto block (blocks[i]);
			auto other_block (other_a.blocks[i]);
			if (block.which () != other_block.which ())
			{
				blocks_equal = false;
			}
			else if (block.which ())
			{
				if (boost::get<nano::block_hash> (block) != boost::get<nano::block_hash> (other_block))
				{
					blocks_equal = false;
				}
			}
			else
			{
				if (!(*boost::get<std::shared_ptr<nano::block>> (block) == *boost::get<std::shared_ptr<nano::block>> (other_block)))
				{
					blocks_equal = false;
				}
			}
		}
	}
	return timestamp == other_a.timestamp && blocks_equal && account == other_a.account && signature == other_a.signature;
}

bool nano::vote::operator!= (nano::vote const & other_a) const
{
	return !(*this == other_a);
}

void nano::vote::serialize_json (boost::property_tree::ptree & tree) const
{
	tree.put ("account", account.to_account ());
	tree.put ("signature", signature.number ());
	tree.put ("sequence", std::to_string (timestamp));
	tree.put ("timestamp", std::to_string (timestamp));
	boost::property_tree::ptree blocks_tree;
	for (auto block : blocks)
	{
		boost::property_tree::ptree entry;
		if (block.which ())
		{
			entry.put ("", boost::get<nano::block_hash> (block).to_string ());
		}
		else
		{
			entry.put ("", boost::get<std::shared_ptr<nano::block>> (block)->hash ().to_string ());
		}
		blocks_tree.push_back (std::make_pair ("", entry));
	}
	tree.add_child ("blocks", blocks_tree);
}

std::string nano::vote::to_json () const
{
	std::stringstream stream;
	boost::property_tree::ptree tree;
	serialize_json (tree);
	boost::property_tree::write_json (stream, tree);
	return stream.str ();
}

nano::vote::vote (nano::vote const & other_a) :
	timestamp{ other_a.timestamp },
	blocks (other_a.blocks),
	account (other_a.account),
	signature (other_a.signature)
{
}

nano::vote::vote (bool & error_a, nano::stream & stream_a, nano::block_uniquer * uniquer_a)
{
	error_a = deserialize (stream_a, uniquer_a);
}

nano::vote::vote (bool & error_a, nano::stream & stream_a, nano::block_type type_a, nano::block_uniquer * uniquer_a)
{
	try
	{
		nano::read (stream_a, account.bytes);
		nano::read (stream_a, signature.bytes);
		nano::read (stream_a, timestamp);

		while (stream_a.in_avail () > 0)
		{
			if (type_a == nano::block_type::not_a_block)
			{
				nano::block_hash block_hash;
				nano::read (stream_a, block_hash);
				blocks.push_back (block_hash);
			}
			else
			{
				auto block (nano::deserialize_block (stream_a, type_a, uniquer_a));
				if (block == nullptr)
				{
					throw std::runtime_error ("Block is null");
				}
				blocks.push_back (block);
			}
		}
	}
	catch (std::runtime_error const &)
	{
		error_a = true;
	}

	if (blocks.empty ())
	{
		error_a = true;
	}
}

nano::vote::vote (nano::account const & account_a, nano::raw_key const & prv_a, uint64_t timestamp_a, std::shared_ptr<nano::block> const & block_a) :
	timestamp{ timestamp_a },
	blocks (1, block_a),
	account (account_a),
	signature (nano::sign_message (prv_a, account_a, hash ()))
{
}

nano::vote::vote (nano::account const & account_a, nano::raw_key const & prv_a, uint64_t timestamp_a, std::vector<nano::block_hash> const & blocks_a) :
	timestamp{ timestamp_a },
	account (account_a)
{
	debug_assert (!blocks_a.empty ());
	debug_assert (blocks_a.size () <= 12);
	blocks.reserve (blocks_a.size ());
	std::copy (blocks_a.cbegin (), blocks_a.cend (), std::back_inserter (blocks));
	signature = nano::sign_message (prv_a, account_a, hash ());
}

std::string nano::vote::hashes_string () const
{
	std::string result;
	for (auto hash : *this)
	{
		result += hash.to_string ();
		result += ", ";
	}
	return result;
}

const std::string nano::vote::hash_prefix = "vote ";

nano::block_hash nano::vote::hash () const
{
	nano::block_hash result;
	blake2b_state hash;
	blake2b_init (&hash, sizeof (result.bytes));
	if (blocks.size () > 1 || (!blocks.empty () && blocks.front ().which ()))
	{
		blake2b_update (&hash, hash_prefix.data (), hash_prefix.size ());
	}
	for (auto block_hash : *this)
	{
		blake2b_update (&hash, block_hash.bytes.data (), sizeof (block_hash.bytes));
	}
	union
	{
		uint64_t qword;
		std::array<uint8_t, 8> bytes;
	};
	qword = timestamp;
	blake2b_update (&hash, bytes.data (), sizeof (bytes));
	blake2b_final (&hash, result.bytes.data (), sizeof (result.bytes));
	return result;
}

nano::block_hash nano::vote::full_hash () const
{
	nano::block_hash result;
	blake2b_state state;
	blake2b_init (&state, sizeof (result.bytes));
	blake2b_update (&state, hash ().bytes.data (), sizeof (hash ().bytes));
	blake2b_update (&state, account.bytes.data (), sizeof (account.bytes.data ()));
	blake2b_update (&state, signature.bytes.data (), sizeof (signature.bytes.data ()));
	blake2b_final (&state, result.bytes.data (), sizeof (result.bytes));
	return result;
}

void nano::vote::serialize (nano::stream & stream_a, nano::block_type type) const
{
	write (stream_a, account);
	write (stream_a, signature);
	write (stream_a, timestamp);
	for (auto const & block : blocks)
	{
		if (block.which ())
		{
			debug_assert (type == nano::block_type::not_a_block);
			write (stream_a, boost::get<nano::block_hash> (block));
		}
		else
		{
			if (type == nano::block_type::not_a_block)
			{
				write (stream_a, boost::get<std::shared_ptr<nano::block>> (block)->hash ());
			}
			else
			{
				boost::get<std::shared_ptr<nano::block>> (block)->serialize (stream_a);
			}
		}
	}
}

void nano::vote::serialize (nano::stream & stream_a) const
{
	write (stream_a, account);
	write (stream_a, signature);
	write (stream_a, timestamp);
	for (auto const & block : blocks)
	{
		if (block.which ())
		{
			write (stream_a, nano::block_type::not_a_block);
			write (stream_a, boost::get<nano::block_hash> (block));
		}
		else
		{
			nano::serialize_block (stream_a, *boost::get<std::shared_ptr<nano::block>> (block));
		}
	}
}

bool nano::vote::deserialize (nano::stream & stream_a, nano::block_uniquer * uniquer_a)
{
	auto error (false);
	try
	{
		nano::read (stream_a, account);
		nano::read (stream_a, signature);
		nano::read (stream_a, timestamp);

		nano::block_type type;

		while (true)
		{
			if (nano::try_read (stream_a, type))
			{
				// Reached the end of the stream
				break;
			}

			if (type == nano::block_type::not_a_block)
			{
				nano::block_hash block_hash;
				nano::read (stream_a, block_hash);
				blocks.push_back (block_hash);
			}
			else
			{
				auto block (nano::deserialize_block (stream_a, type, uniquer_a));
				if (block == nullptr)
				{
					throw std::runtime_error ("Block is empty");
				}

				blocks.push_back (block);
			}
		}
	}
	catch (std::runtime_error const &)
	{
		error = true;
	}

	if (blocks.empty ())
	{
		error = true;
	}

	return error;
}

bool nano::vote::validate () const
{
	return nano::validate_message (account, hash (), signature);
}

nano::block_hash nano::iterate_vote_blocks_as_hash::operator() (boost::variant<std::shared_ptr<nano::block>, nano::block_hash> const & item) const
{
	nano::block_hash result;
	if (item.which ())
	{
		result = boost::get<nano::block_hash> (item);
	}
	else
	{
		result = boost::get<std::shared_ptr<nano::block>> (item)->hash ();
	}
	return result;
}

boost::transform_iterator<nano::iterate_vote_blocks_as_hash, nano::vote_blocks_vec_iter> nano::vote::begin () const
{
	return boost::transform_iterator<nano::iterate_vote_blocks_as_hash, nano::vote_blocks_vec_iter> (blocks.begin (), nano::iterate_vote_blocks_as_hash ());
}

boost::transform_iterator<nano::iterate_vote_blocks_as_hash, nano::vote_blocks_vec_iter> nano::vote::end () const
{
	return boost::transform_iterator<nano::iterate_vote_blocks_as_hash, nano::vote_blocks_vec_iter> (blocks.end (), nano::iterate_vote_blocks_as_hash ());
}

nano::vote_uniquer::vote_uniquer (nano::block_uniquer & uniquer_a) :
	uniquer (uniquer_a)
{
}

std::shared_ptr<nano::vote> nano::vote_uniquer::unique (std::shared_ptr<nano::vote> const & vote_a)
{
	auto result (vote_a);
	if (result != nullptr && !result->blocks.empty ())
	{
		if (!result->blocks.front ().which ())
		{
			result->blocks.front () = uniquer.unique (boost::get<std::shared_ptr<nano::block>> (result->blocks.front ()));
		}
		nano::block_hash key (vote_a->full_hash ());
		nano::lock_guard<nano::mutex> lock (mutex);
		auto & existing (votes[key]);
		if (auto block_l = existing.lock ())
		{
			result = block_l;
		}
		else
		{
			existing = vote_a;
		}

		release_assert (std::numeric_limits<CryptoPP::word32>::max () > votes.size ());
		for (auto i (0); i < cleanup_count && !votes.empty (); ++i)
		{
			auto random_offset = nano::random_pool::generate_word32 (0, static_cast<CryptoPP::word32> (votes.size () - 1));

			auto existing (std::next (votes.begin (), random_offset));
			if (existing == votes.end ())
			{
				existing = votes.begin ();
			}
			if (existing != votes.end ())
			{
				if (auto block_l = existing->second.lock ())
				{
					// Still live
				}
				else
				{
					votes.erase (existing);
				}
			}
		}
	}
	return result;
}

size_t nano::vote_uniquer::size ()
{
	nano::lock_guard<nano::mutex> lock (mutex);
	return votes.size ();
}

std::unique_ptr<nano::container_info_component> nano::collect_container_info (vote_uniquer & vote_uniquer, std::string const & name)
{
	auto count = vote_uniquer.size ();
	auto sizeof_element = sizeof (vote_uniquer::value_type);
	auto composite = std::make_unique<container_info_composite> (name);
	composite->add_component (std::make_unique<container_info_leaf> (container_info{ "votes", count, sizeof_element }));
	return composite;
}

nano::genesis::genesis ()
{
	static nano::network_params network_params;
	open = parse_block_from_genesis_data (network_params.ledger.genesis_block);
	debug_assert (open != nullptr);
}

nano::block_hash nano::genesis::hash () const
{
	return open->hash ();
}

nano::wallet_id nano::random_wallet_id ()
{
	nano::wallet_id wallet_id;
	nano::uint256_union dummy_secret;
	random_pool::generate_block (dummy_secret.bytes.data (), dummy_secret.bytes.size ());
	ed25519_publickey (dummy_secret.bytes.data (), wallet_id.bytes.data ());
	return wallet_id;
}

nano::unchecked_key::unchecked_key (nano::hash_or_account const & previous_a, nano::block_hash const & hash_a) :
	previous (previous_a.hash),
	hash (hash_a)
{
}

nano::unchecked_key::unchecked_key (nano::uint512_union const & union_a) :
	previous (union_a.uint256s[0].number ()),
	hash (union_a.uint256s[1].number ())
{
}

bool nano::unchecked_key::deserialize (nano::stream & stream_a)
{
	auto error (false);
	try
	{
		nano::read (stream_a, previous.bytes);
		nano::read (stream_a, hash.bytes);
	}
	catch (std::runtime_error const &)
	{
		error = true;
	}

	return error;
}

bool nano::unchecked_key::operator== (nano::unchecked_key const & other_a) const
{
	return previous == other_a.previous && hash == other_a.hash;
}

nano::block_hash const & nano::unchecked_key::key () const
{
	return previous;
}

void nano::generate_cache::enable_all ()
{
	reps = true;
	cemented_count = true;
	unchecked_count = true;
	account_count = true;
}
