use starknet::{
    ContractAddress, SyscallResult,
    storage_access::{Store, StorageBaseAddress}
};

#[derive(Destruct)]
struct Balance {
    amount: u128
}

impl U128IntoBalance of Into<u128, Balance> {
    fn into(self: u128) -> Balance {
        Balance { amount: self }
    }
}

impl BalanceAdd of Add<Balance> {
    fn add(lhs: Balance, rhs: Balance) -> Balance {
        Balance { amount: lhs.amount + rhs.amount }
    }
}

impl BalanceSub of Sub<Balance> {
    fn sub(lhs: Balance, rhs: Balance) -> Balance {
        Balance { amount: lhs.amount - rhs.amount }
    }
}

impl BalanceSerde of Serde<Balance> {
    fn serialize(self: @Balance, ref output: Array<felt252>) {
        self.amount.serialize(ref output);
    }

    fn deserialize(ref serialized: Span<felt252>) -> Option<Balance> {
        Option::Some(Balance { amount: integer::U128Serde::deserialize(ref serialized)? })
    }
}

impl BalanceStore of Store<Balance> {
    fn read(address_domain: u32, base: StorageBaseAddress) -> SyscallResult<Balance> {
        SyscallResult::Ok(Balance { amount: Store::<u128>::read(address_domain, base)? })
    }

    fn write(address_domain: u32, base: StorageBaseAddress, value: Balance) -> SyscallResult<()> {
        Store::<u128>::write(address_domain, base, value.amount)
    }

    fn read_at_offset(
        address_domain: u32, base: StorageBaseAddress, offset: u8
    ) -> SyscallResult<Balance> {
        SyscallResult::Ok(Balance { amount: Store::<u128>::read_at_offset(address_domain, base, offset)? })
    }

    fn write_at_offset(
        address_domain: u32, base: StorageBaseAddress, offset: u8, value: Balance
    ) -> SyscallResult<()> {
        Store::<u128>::write_at_offset(address_domain, base, offset, value.amount)
    }

    fn size() -> u8 {
        Store::<u128>::size()
    }
}

#[starknet::interface]
trait IERC20Linear<TState> {
    fn name(self: @TState) -> felt252;
    fn symbol(self: @TState) -> felt252;
    fn decimals(self: @TState) -> u8;

    fn total_supply(self: @TState) -> Balance;
    fn balance_of(self: @TState, account: ContractAddress) -> Balance;
    fn allowance(self: @TState, owner: ContractAddress, spender: ContractAddress) -> Balance;

    fn approve(ref self: TState, spender: ContractAddress, amount: Balance) -> bool;
    fn transfer(ref self: TState, recipient: ContractAddress, amount: Balance) -> bool;
    fn transfer_from(
        ref self: TState, sender: ContractAddress, recipient: ContractAddress, amount: Balance
    ) -> bool;

    fn mint_to(ref self: TState, recipient: ContractAddress, amount: Balance);
    fn burn_from(ref self: TState, holder: ContractAddress, amount: Balance);
}


#[starknet::contract]
mod ERC20 {
    use ltoken::token::IERC20Linear;
    use starknet::{ContractAddress};

    use super::Balance;
    use auth::ownable;

    // TODO: events

    #[storage]
    struct Storage {
        name: felt252,
        symbol: felt252,
        supply: Balance,
        balances: LegacyMap<ContractAddress, Balance>,
        allowances: LegacyMap<(ContractAddress, ContractAddress), Balance>,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        name: felt252,
        symbol: felt252,
        owner: ContractAddress,
    ) {
        self.name.write(name);
        self.symbol.write(symbol);
        ownable::set_owner(owner);
    }

    #[external(v0)]
    impl ERC20Impl of super::IERC20Linear<ContractState> {
        fn name(self: @ContractState) -> felt252 {
            self.name.read()
        }

        fn symbol(self: @ContractState) -> felt252 {
            self.symbol.read()
        }

        fn decimals(self: @ContractState) -> u8 {
            18
        }

        fn total_supply(self: @ContractState) -> Balance {
            self.supply.read()
        }

        fn balance_of(self: @ContractState, account: ContractAddress) -> Balance {
            self.balances.read(account)
        }

        fn allowance(self: @ContractState, owner: ContractAddress, spender: ContractAddress) -> Balance {
            self.allowances.read((owner, spender))
        }

        fn approve(ref self: ContractState, spender: ContractAddress, amount: Balance) -> bool {
            self.allowances.write((starknet::get_caller_address(), spender), amount);
            true
        }

        fn transfer(ref self: ContractState, recipient: ContractAddress, amount: Balance) -> bool {
            self.do_transfer(starknet::get_caller_address(), recipient, amount);
            true
        }

        fn transfer_from(
            ref self: ContractState, sender: ContractAddress, recipient: ContractAddress, amount: Balance
        ) -> bool {
            let spent_amount = Balance { amount: amount.amount };

            self.use_allowance(sender, starknet::get_caller_address(), spent_amount);
            self.do_transfer(sender, recipient, amount);
            true
        }

        fn mint_to(ref self: ContractState, recipient: ContractAddress, amount: Balance) {
            ownable::assert_owner(starknet::get_caller_address());

            let minted_amount = Balance { amount: amount.amount };

            self.supply.write(self.supply.read() + amount);
            let recipient_balance = self.balances.read(recipient);
            self.balances.write(recipient, recipient_balance + minted_amount);
        }

        fn burn_from(ref self: ContractState, holder: ContractAddress, amount: Balance) {
            let burned_amount = Balance { amount: amount.amount };
            let spent_amount = Balance { amount: amount.amount };

            self.use_allowance(holder, starknet::get_caller_address(), spent_amount);
            self.supply.write(self.supply.read() - amount);
            let holder_balance = self.balances.read(holder);
            self.balances.write(holder, holder_balance - burned_amount);
        }
    }

    #[generate_trait]
    impl Internal of InternalTrait {
        fn do_transfer(ref self: ContractState, sender: ContractAddress, recipient: ContractAddress, amount: Balance) {
            let gains = Balance { amount: amount.amount };

            self.balances.write(sender, self.balances.read(sender) - amount);
            self.balances.write(recipient, self.balances.read(recipient) + gains);
        }

        fn use_allowance(ref self: ContractState, owner: ContractAddress, spender: ContractAddress, amount: Balance) {
            let allowance = self.allowances.read((owner, spender));
            self.allowances.write((owner, spender), allowance - amount);
            // TODO: unlimited allowance
        }
    }
}

#[cfg(test)]
mod test {
    use super::{ERC20, IERC20LinearDispatcher, IERC20LinearDispatcherTrait};
    use starknet::{deploy_syscall, ContractAddress, SyscallResult, SyscallResultTrait};
    use starknet::testing::{set_contract_address};

    fn as_addr(v: felt252) -> ContractAddress {
        starknet::contract_address::contract_address_try_from_felt252(v).unwrap()
    }

    fn owner() -> ContractAddress {
        as_addr('owner')
    }

    fn dude() -> ContractAddress {
        as_addr('dude')
    }

    fn deploy_token() -> IERC20LinearDispatcher {
        let class_hash = starknet::class_hash_try_from_felt252(ERC20::TEST_CLASS_HASH).unwrap();
        let calldata = array![
            'Token',
            'TKN',
            owner().into()
        ];

        let (addr, _) = deploy_syscall(class_hash, 0, calldata.span(), false).unwrap_syscall();
        IERC20LinearDispatcher { contract_address: addr }
    }

    fn mint_to_owner(token: IERC20LinearDispatcher, amount: u128) {
        token.mint_to(owner(), amount.into());
    }

    #[test]
    #[available_gas(100000000)]
    fn test_deploy() {
        let token: IERC20LinearDispatcher = deploy_token();
        assert(token.name() == 'Token', 'name');
        assert(token.symbol() == 'TKN', 'symbol');
        assert(token.decimals() == 18, 'decimals');
        assert(token.total_supply().amount == 0, 'total_supply');
    }

    #[test]
    #[available_gas(100000000)]
    fn test_transfer() {
        let token: IERC20LinearDispatcher = deploy_token();
        set_contract_address(owner());

        let mint_amount: u128 = 1000000000000000;
        mint_to_owner(token, mint_amount);

        assert(token.balance_of(owner()).amount == mint_amount, 'balance_of owner 1');
        assert(token.balance_of(dude()).amount == 0, 'balance_of dude 1');

        let transfer_amount: u128 = 5000000;
        token.transfer(dude(), transfer_amount.into());

        assert(token.balance_of(owner()).amount == mint_amount - transfer_amount, 'balance_of owner 2');
        assert(token.balance_of(dude()).amount == transfer_amount, 'balance_of dude 2');
    }

    #[test]
    #[available_gas(100000000)]
    fn test_mint() {
        let token: IERC20LinearDispatcher = deploy_token();
        set_contract_address(owner());

        assert(token.balance_of(owner()).amount == 0, 'pre mint owner bal');
        assert(token.balance_of(dude()).amount == 0, 'pre mint dude bal');

        let mint_amount: u128 = 1000000000000000;
        token.mint_to(dude(), mint_amount.into());

        assert(token.balance_of(owner()).amount == 0, 'post mint owner bal');
        assert(token.balance_of(dude()).amount == mint_amount, 'post mint dude bal');
        assert(token.total_supply().amount == mint_amount, 'post mint total supply');
    }

    #[test]
    #[available_gas(100000000)]
    fn test_transfer_to_self() {
        let token: IERC20LinearDispatcher = deploy_token();
        set_contract_address(owner());

        assert(token.balance_of(owner()).amount == 0, 'pre mint owner bal');
        assert(token.balance_of(dude()).amount == 0, 'pre mint dude bal');

        let mint_amount: u128 = 1000000000000000;
        token.mint_to(dude(), mint_amount.into());

        assert(token.balance_of(dude()).amount == mint_amount.into(), 'post mint dude bal');

        let transfer_amount: u128 = 10000000;

        set_contract_address(dude());
        token.approve(dude(), transfer_amount.into());
        token.transfer_from(dude(), dude(), transfer_amount.into());

        assert(token.balance_of(dude()).amount == mint_amount.into(), 'post self transfer dude bal');
        assert(token.total_supply().amount == mint_amount, 'post self transfer total supply');
    }

    // TODO: more tests
}
