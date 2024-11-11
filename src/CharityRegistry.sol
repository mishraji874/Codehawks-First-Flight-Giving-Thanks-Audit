// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// @audit-low missing documentation
contract CharityRegistry {
    address public admin;
    // @audit-info boolean optimizations in mappings
    mapping(address => bool) public verifiedCharities;
    mapping(address => bool) public registeredCharities;

    constructor() {
        admin = msg.sender;
    }

    // @audit-high No Access Control on Registration
    // @audit-medium Missing Zero Address Validation
    function registerCharity(address charity) public {
        registeredCharities[charity] = true;
    }

    // @audit-info reduntant state checks
    function verifyCharity(address charity) public {
        require(msg.sender == admin, "Only admin can verify");
        require(registeredCharities[charity], "Charity not registered");
        verifiedCharities[charity] = true;
    }

    // @audit-high incorrect verification logic
    // @audit-info public function not called by the contract
    function isVerified(address charity) public view returns (bool) {
        return registeredCharities[charity];
    }

    // @audit-medium Missing Zero Address Validation
    // @audit-low no two step admin transfer
    function changeAdmin(address newAdmin) public {
        require(msg.sender == admin, "Only admin can change admin");
        admin = newAdmin;
    }
}
