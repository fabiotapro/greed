pragma solidity 0.8.7;

contract TestMemory {

    function mload(uint offset) private pure returns (bytes32 value) {
        assembly {
            value := mload(offset)
        }
    }


    // memOffset: where to copy the calldata in memory 
    // cdataOffset: where to copy from 
    // size: the amount of bytes to copy from calldata 
    // unknown_index: where to do the 'store over copy' operation
    // unknown_val: what to store at 'unknown_index'
    // expects: the list of 32 bytes slots we expect to read with the load over memcpy
    function test_1(uint256 memOffset, uint256 cdataOffset, uint256 size, uint256 unknown_index, bytes32 unknown_val, bytes32 [] calldata expects) public{
        
        
        // Copy some data from calldata
        assembly{
            calldatacopy(memOffset, cdataOffset, size)
        }

        // We need to move this because of the function signature.
        memOffset += 4;

       
        // Checking that the stuff we just copied matches what we expected
        // (load over memcpy)
        uint slots = size/32;
        for(uint i=0; i<slots; i++){
            if(mload(memOffset+i*32) != expects[i]){
                assembly{log1(0,0, "error:load_over_memcopy")}
                revert();
            }
        }
        assembly{log1(0,0, "success:load_over_memcopy")}

        // Modify one of the bytes in memory 
        // (store over memcpy)
        uint256 newMemOffset = memOffset+unknown_index;
        assembly{
             mstore(newMemOffset, unknown_val)
        }

        // (load over store over memcpy)
        // This is very fast to solve.
        if(mload(newMemOffset) != unknown_val){
            assembly{log1(0,0, "error:load_over_store")}
            revert();
        }
        assembly{log1(0,0, "success:load_over_store")}

        
        // write over all the memcpy done before
        for(uint j=0; j<slots; j++){
            uint256 newIndex = newMemOffset+j*32;
            assembly{
                mstore(newIndex, 0x46)
            } 
        }

        // Checking if we can read over the previous stores.
        for(uint z=0; z<slots; z++){
            if(mload(memOffset+z*32) != 0x0000000000000000000000000000000000000000000000000000000000000046){
                assembly{log1(0,0, "error:load_over_store_all")}
                revert();
            }
        }
        assembly{log1(0,0, "success:load_over_store_all")}

        // Copying again with calldatacopy
        assembly{
            calldatacopy(memOffset, cdataOffset, size)
        }

        memOffset += 4;

        // Checking if we still have the original array here! 
        for(uint w=0; w<slots; w++){
            if(mload(memOffset+w*32) != expects[w]){
                assembly{log1(0,0, "error:load_after_calldatacopy")}
                revert();
            }
        }
        assembly{log1(0,0, "success:load_after_calldatacopy")}

        // Overwriting all but the last byte
        uint xx = 0;
        for(xx=0; xx<slots-1; xx++){
            uint256 newIndex = memOffset+xx*32;
            assembly{
                mstore(newIndex, 0x55)
            } 
        }

        // Overwriting last but one byte
        uint xy = 0;
        for(xy=0; xy<slots-2; xy++){
            uint256 newIndex = memOffset+xy*32;
            assembly{
                mstore(newIndex, 0x65)
            } 
        }
        
        if(mload(memOffset+xx*32) != expects[slots-1] && mload(memOffset+xx-1*32) != 0x0000000000000000000000000000000000000000000000000000000000000055 ){
            assembly{log1(0,0, "error:load_after_calldatacopy2")}
            revert();
        }
        assembly{log1(0,0, "success:load_after_calldatacopy2")}

        if(mload(memOffset+xx*32) != expects[slots-1] && mload(memOffset+xy*32) != expects[slots-2] && 
                    mload(memOffset+xx-1*32) != 0x0000000000000000000000000000000000000000000000000000000000000055 && 
                            mload(memOffset+xy-2*32) != 0x0000000000000000000000000000000000000000000000000000000000000065){
            assembly{log1(0,0, "error:load_after_calldatacopy3")}
            revert();
        }
        assembly{log1(0,0, "success:load_after_calldatacopy3")}

        assembly {log1(0, 0, "success:")}
    }
}
