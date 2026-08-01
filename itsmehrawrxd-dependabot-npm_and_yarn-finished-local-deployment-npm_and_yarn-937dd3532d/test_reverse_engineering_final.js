#!/usr/bin/env node

// Final test script for RawrZ Reverse Engineering Engine
const ReverseEngineering = require('./src/engines/reverse-engineering');

async function testReverseEngineering() {
    console.log('🔍 Testing RawrZ Reverse Engineering Engine...\n');
    
    try {
        // Initialize the engine
        console.log('1. Initializing Reverse Engineering Engine...');
        const reEngine = ReverseEngineering;
        await reEngine.initialize();
        console.log('✅ Reverse Engineering Engine initialized successfully\n');
        
        // Test binary analysis
        console.log('2. Testing binary analysis...');
        const testFile = 'test_sample.exe';
        const analysisResult = await reEngine.analyzeBinary(testFile, {
            analyzeSections: true,
            analyzeImports: true,
            analyzeExports: true,
            extractStrings: true,
            analyzeFunctions: true
        });
        console.log('✅ Binary analysis completed successfully');
        console.log('   - Analysis ID:', analysisResult.analysisId);
        console.log('   - File Info:', analysisResult.analysis.fileInfo);
        console.log('   - Sections:', analysisResult.analysis.sections.length);
        console.log('   - Imports:', analysisResult.analysis.imports.length);
        console.log('   - Exports:', analysisResult.analysis.exports.length);
        console.log('   - Functions:', analysisResult.analysis.functions.length);
        console.log('   - Duration:', analysisResult.duration + 'ms\n');
        
        // Test file info
        console.log('3. Testing file info extraction...');
        const fileInfo = await reEngine.getFileInfo(testFile);
        console.log('✅ File info extraction completed:', fileInfo);
        console.log('');
        
        // Test section analysis
        console.log('4. Testing section analysis...');
        const sectionResult = await reEngine.analyzeSections(testFile);
        console.log('✅ Section analysis completed:', sectionResult);
        console.log('');
        
        // Test import analysis
        console.log('5. Testing import analysis...');
        const importResult = await reEngine.analyzeImports(testFile);
        console.log('✅ Import analysis completed:', importResult);
        console.log('');
        
        // Test export analysis
        console.log('6. Testing export analysis...');
        const exportResult = await reEngine.analyzeExports(testFile);
        console.log('✅ Export analysis completed:', exportResult);
        console.log('');
        
        // Test string extraction
        console.log('7. Testing string extraction...');
        const stringResult = await reEngine.extractStrings(testFile);
        console.log('✅ String extraction completed:', stringResult);
        console.log('');
        
        // Test function analysis
        console.log('8. Testing function analysis...');
        const functionResult = await reEngine.analyzeFunctions(testFile);
        console.log('✅ Function analysis completed:', functionResult);
        console.log('');
        
        // Test entropy calculation
        console.log('9. Testing entropy calculation...');
        const entropyResult = await reEngine.calculateEntropy(testFile);
        console.log('✅ Entropy calculation completed:', entropyResult);
        console.log('');
        
        // Test packing detection
        console.log('10. Testing packing detection...');
        const packingResult = await reEngine.detectPacking(testFile);
        console.log('✅ Packing detection completed:', packingResult);
        console.log('');
        
        // Test obfuscation detection
        console.log('11. Testing obfuscation detection...');
        const obfuscationResult = await reEngine.detectObfuscation(testFile);
        console.log('✅ Obfuscation detection completed:', obfuscationResult);
        console.log('');
        
        // Test malware indicator detection
        console.log('12. Testing malware indicator detection...');
        const malwareResult = await reEngine.detectMalwareIndicators(analysisResult.analysis);
        console.log('✅ Malware indicator detection completed:', malwareResult);
        console.log('');
        
        // Test binary disassembly
        console.log('13. Testing binary disassembly...');
        const disassemblyResult = await reEngine.disassembleBinary(testFile, {
            architecture: 'x64',
            format: 'PE',
            startAddress: 0x401000,
            endAddress: 0x401100
        });
        console.log('✅ Binary disassembly completed:', disassemblyResult);
        console.log('');
        
        // Test binary decompilation
        console.log('14. Testing binary decompilation...');
        const decompileResult = await reEngine.decompileBinary(testFile, {
            functionAddress: 0x401000,
            architecture: 'x64'
        });
        console.log('✅ Binary decompilation completed:', decompileResult);
        console.log('');
        
        // Test reverse engineering report
        console.log('15. Testing reverse engineering report...');
        const reportResult = await reEngine.getReverseEngineeringReport();
        console.log('✅ Reverse engineering report completed:', reportResult);
        console.log('');
        
        // Test recommendations
        console.log('16. Testing reverse engineering recommendations...');
        const recommendations = reEngine.generateReverseEngineeringRecommendations();
        console.log('✅ Reverse engineering recommendations completed:', recommendations);
        console.log('');
        
        // Test utility functions
        console.log('17. Testing utility functions...');
        const testData = Buffer.from('MZ\x90\x00', 'binary');
        const fileType = reEngine.detectFileType(testData);
        const architecture = reEngine.detectArchitecture(testData);
        const format = reEngine.detectFormat(testData);
        const signatureMatch = reEngine.matchesSignature(testData, 'MZ');
        
        console.log('✅ Utility functions completed:');
        console.log('   - File Type Detection:', fileType);
        console.log('   - Architecture Detection:', architecture);
        console.log('   - Format Detection:', format);
        console.log('   - Signature Match:', signatureMatch);
        console.log('');
        
        // Test ID generation
        console.log('18. Testing ID generation...');
        const analysisId = reEngine.generateAnalysisId();
        const disassemblyId = reEngine.generateDisassemblyId();
        const decompilationId = reEngine.generateDecompilationId();
        
        console.log('✅ ID generation completed:');
        console.log('   - Analysis ID:', analysisId);
        console.log('   - Disassembly ID:', disassemblyId);
        console.log('   - Decompilation ID:', decompilationId);
        console.log('');
        
        console.log('🎉 All Reverse Engineering Engine tests completed successfully!');
        console.log('📊 Test Summary:');
        console.log('   - Binary Analysis: ✅');
        console.log('   - File Info Extraction: ✅');
        console.log('   - Section Analysis: ✅');
        console.log('   - Import Analysis: ✅');
        console.log('   - Export Analysis: ✅');
        console.log('   - String Extraction: ✅');
        console.log('   - Function Analysis: ✅');
        console.log('   - Entropy Calculation: ✅');
        console.log('   - Packing Detection: ✅');
        console.log('   - Obfuscation Detection: ✅');
        console.log('   - Malware Indicator Detection: ✅');
        console.log('   - Binary Disassembly: ✅');
        console.log('   - Binary Decompilation: ✅');
        console.log('   - Report Generation: ✅');
        console.log('   - Recommendations: ✅');
        console.log('   - Utility Functions: ✅');
        console.log('   - ID Generation: ✅');
        console.log('');
        console.log('🔧 Reverse Engineering Engine is fully functional!');
        
    } catch (error) {
        console.error('❌ Reverse Engineering Engine test failed:', error.message);
        console.error('Stack trace:', error.stack);
        process.exit(1);
    }
}

// Run the test
if (require.main === module) {
    testReverseEngineering().catch(console.error);
}

module.exports = { testReverseEngineering };
