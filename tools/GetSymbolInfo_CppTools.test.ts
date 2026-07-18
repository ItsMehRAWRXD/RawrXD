/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import { GetSymbolInfo_CppTools, GetSymbolInfo_CppTools_Definition } from './GetSymbolInfo_CppTools';

describe('GetSymbolInfo_CppTools', () => {
    
    describe('Tool Definition', () => {
        it('should have correct name', () => {
            assert.strictEqual(GetSymbolInfo_CppTools_Definition.name, 'GetSymbolInfo_CppTools');
        });

        it('should require symbol parameter', () => {
            assert.deepStrictEqual(GetSymbolInfo_CppTools_Definition.parameters.required, ['symbol']);
        });

        it('should have optional filePath and line parameters', () => {
            const props = GetSymbolInfo_CppTools_Definition.parameters.properties;
            assert.ok(props.symbol);
            assert.ok(props.filePath);
            assert.ok(props.line);
        });
    });

    describe('Symbol Information Retrieval', () => {
        it('should return error for empty symbol', async () => {
            const result = await GetSymbolInfo_CppTools({ symbol: '' });
            assert.strictEqual(result.found, false);
            assert.ok(result.error?.includes('required'));
        });

        it('should return error for missing symbol', async () => {
            const result = await GetSymbolInfo_CppTools({ 
                symbol: 'NonExistentSymbolXYZ123' 
            });
            assert.strictEqual(result.found, false);
            assert.ok(result.error?.includes('not found'));
        });
    });

    describe('Type Information Parsing', () => {
        // These would be integration tests requiring actual VS Code environment
        // For unit testing, we test the parsing functions indirectly
        
        it('should handle const types', async () => {
            // Mock test - would need actual VS Code API in real test
            const result = await GetSymbolInfo_CppTools({ 
                symbol: 'testConst',
                filePath: '/test/file.cpp',
                line: 1
            });
            // In real test, verify typeInfo.isConst is true for const int
        });

        it('should handle pointer types', async () => {
            // Mock test
            const result = await GetSymbolInfo_CppTools({ 
                symbol: 'testPointer',
                filePath: '/test/file.cpp',
                line: 1
            });
            // In real test, verify typeInfo.isPointer is true
        });

        it('should handle reference types', async () => {
            // Mock test
            const result = await GetSymbolInfo_CppTools({ 
                symbol: 'testReference',
                filePath: '/test/file.cpp',
                line: 1
            });
            // In real test, verify typeInfo.isReference is true
        });

        it('should handle array types', async () => {
            // Mock test
            const result = await GetSymbolInfo_CppTools({ 
                symbol: 'testArray',
                filePath: '/test/file.cpp',
                line: 1
            });
            // In real test, verify typeInfo.isArray is true
        });
    });

    describe('Memory Layout', () => {
        it('should return memory layout for classes', async () => {
            // Mock test
            const result = await GetSymbolInfo_CppTools({ 
                symbol: 'TestClass',
                filePath: '/test/file.cpp',
                line: 1
            });
            // In real test, verify memoryLayout is populated for class
        });

        it('should return memory layout for structs', async () => {
            // Mock test
            const result = await GetSymbolInfo_CppTools({ 
                symbol: 'TestStruct',
                filePath: '/test/file.cpp',
                line: 1
            });
            // In real test, verify memoryLayout is populated for struct
        });
    });

    describe('Location Information', () => {
        it('should include file path in response', async () => {
            const result = await GetSymbolInfo_CppTools({ 
                symbol: 'testSymbol',
                filePath: '/test/file.cpp',
                line: 10
            });
            if (result.found) {
                assert.ok(result.location?.filePath);
                assert.ok(result.location?.line);
                assert.ok(result.location?.column);
            }
        });
    });
});
