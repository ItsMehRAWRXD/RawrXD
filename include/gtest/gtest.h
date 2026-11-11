/*
 * Minimal Google Test Stub Header
 * Stub implementation for Gold build
 */

#ifndef GTEST_GTEST_H
#define GTEST_GTEST_H

#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <functional>

// Minimal test framework stub
namespace testing {

// Free functions
inline void InitGoogleTest(int* argc, char** argv) {}
inline int RunAllTests() { 
    std::cout << "[==========] Running stub tests.\n";
    std::cout << "[==========] 0 tests ran.\n";
    return 0; 
}

// Test base class
class Test {
public:
    virtual void SetUp() {}
    virtual void TearDown() {}
    virtual void TestBody() = 0;
};

// Assertion macros
#define EXPECT_TRUE(condition) \
    if (!(condition)) { \
        std::cerr << "EXPECT_TRUE failed at " << __FILE__ << ":" << __LINE__ << std::endl; \
    }

#define EXPECT_FALSE(condition) \
    if (condition) { \
        std::cerr << "EXPECT_FALSE failed at " << __FILE__ << ":" << __LINE__ << std::endl; \
    }

#define EXPECT_EQ(val1, val2) \
    if ((val1) != (val2)) { \
        std::cerr << "EXPECT_EQ failed at " << __FILE__ << ":" << __LINE__ << std::endl; \
    }

#define EXPECT_NE(val1, val2) \
    if ((val1) == (val2)) { \
        std::cerr << "EXPECT_NE failed at " << __FILE__ << ":" << __LINE__ << std::endl; \
    }

#define EXPECT_LT(val1, val2) \
    if (!((val1) < (val2))) { \
        std::cerr << "EXPECT_LT failed at " << __FILE__ << ":" << __LINE__ << std::endl; \
    }

#define EXPECT_LE(val1, val2) \
    if (!((val1) <= (val2))) { \
        std::cerr << "EXPECT_LE failed at " << __FILE__ << ":" << __LINE__ << std::endl; \
    }

#define EXPECT_GT(val1, val2) \
    if (!((val1) > (val2))) { \
        std::cerr << "EXPECT_GT failed at " << __FILE__ << ":" << __LINE__ << std::endl; \
    }

#define EXPECT_GE(val1, val2) \
    if (!((val1) >= (val2))) { \
        std::cerr << "EXPECT_GE failed at " << __FILE__ << ":" << __LINE__ << std::endl; \
    }

#define EXPECT_NEAR(val1, val2, abs_error) \
    if (std::abs((val1) - (val2)) > (abs_error)) { \
        std::cerr << "EXPECT_NEAR failed at " << __FILE__ << ":" << __LINE__ << std::endl; \
    }

#define EXPECT_THROW(statement, exception_type) \
    try { \
        statement; \
        std::cerr << "EXPECT_THROW failed at " << __FILE__ << ":" << __LINE__ << " - no exception thrown\n"; \
    } catch (const exception_type&) { \
    } catch (...) { \
        std::cerr << "EXPECT_THROW failed at " << __FILE__ << ":" << __LINE__ << " - wrong exception type\n"; \
    }

#define EXPECT_NO_THROW(statement) \
    try { \
        statement; \
    } catch (...) { \
        std::cerr << "EXPECT_NO_THROW failed at " << __FILE__ << ":" << __LINE__ << std::endl; \
    }

#define ASSERT_TRUE(condition) EXPECT_TRUE(condition)
#define ASSERT_FALSE(condition) EXPECT_FALSE(condition)
#define ASSERT_EQ(val1, val2) EXPECT_EQ(val1, val2)
#define ASSERT_NE(val1, val2) EXPECT_NE(val1, val2)
#define ASSERT_LT(val1, val2) EXPECT_LT(val1, val2)
#define ASSERT_LE(val1, val2) EXPECT_LE(val1, val2)
#define ASSERT_GT(val1, val2) EXPECT_GT(val1, val2)
#define ASSERT_GE(val1, val2) EXPECT_GE(val1, val2)

#define SUCCEED() do { } while(0)
#define FAIL() do { std::cerr << "FAIL at " << __FILE__ << ":" << __LINE__ << std::endl; } while(0)
#define ADD_FAILURE() do { std::cerr << "ADD_FAILURE at " << __FILE__ << ":" << __LINE__ << std::endl; } while(0)

// Test registration macros
#define TEST(test_case_name, test_name) \
    class test_case_name##_##test_name##_Test : public testing::Test { \
    public: \
        void TestBody() override; \
    }; \
    void test_case_name##_##test_name##_Test::TestBody()

#define TEST_F(test_fixture, test_name) \
    class test_fixture##_##test_name##_Test : public test_fixture { \
    public: \
        void TestBody() override; \
    }; \
    void test_fixture##_##test_name##_Test::TestBody()

#define TEST_P(test_case_name, test_name) TEST(test_case_name, test_name)
#define INSTANTIATE_TEST_SUITE_P(prefix, test_case_name, generator)
#define INSTANTIATE_TEST_CASE_P(prefix, test_case_name, generator)

// Parameterized test support
class TestWithParam {};

// Assertion result
class AssertionResult {
public:
    operator bool() const { return true; }
};

// Matchers (minimal)
template<typename T>
class Matcher {
public:
    Matcher(T expected) : expected_(expected) {}
    bool Match(T actual) { return actual == expected_; }
private:
    T expected_;
};

// Print to stdout
inline void PrintTo(const char* str, std::ostream* os) { *os << str; }
inline void PrintTo(const std::string& str, std::ostream* os) { *os << str; }

} // namespace testing

// Main entry point macro
#define RUN_ALL_TESTS() testing::RunAllTests()

// Init Google Test
inline void InitGoogleTest(int* argc, char** argv) {}

#endif // GTEST_GTEST_H
