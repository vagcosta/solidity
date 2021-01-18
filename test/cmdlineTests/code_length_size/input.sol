// SPDX-License-Identifier: GPL-3.0
contract C {
    uint len1;
    uint len2;
    constructor() {
        len1 = address(this).code.length;
        len2 = address(this).code.length;

    }
    function f() public view returns (uint r1, uint r2) {
        r1 = address(this).code.length;
        address a = address(0);
        r2 = a.code.length;
    }
}
