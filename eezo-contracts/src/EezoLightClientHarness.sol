// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import { EezoLightClient } from "./EezoLightClient.sol";

contract EezoLightClientHarness is EezoLightClient {
    constructor() EezoLightClient(address(0)) {}
    function __setHeader(HeaderV2 memory h) external { headers[h.height] = h; }
}
