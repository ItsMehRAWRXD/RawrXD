// test_browser.cpp - Unit tests for RawrXD Browser
// Simple test harness for browser components

#include "RawrXD_Browser.h"
#include <iostream>
#include <assert>

using namespace RawrXD;

// Test utilities
#define TEST(name) void test_##name()
#define RUN_TEST(name) do { \
    std::cout << "Running " #name "... "; \
    test_##name(); \
    std::cout << "PASSED" << std::endl; \
} while(0)

#define ASSERT_TRUE(expr) assert(expr)
#define ASSERT_FALSE(expr) assert(!(expr))
#define ASSERT_EQ(a, b) assert((a) == (b))
#define ASSERT_NE(a, b) assert((a) != (b))

// ============================================================================
// BrowserUtils Tests
// ============================================================================

TEST(url_parsing) {
    using namespace BrowserUtils;
    
    // IsAbsoluteURL
    ASSERT_TRUE(IsAbsoluteURL("http://example.com"));
    ASSERT_TRUE(IsAbsoluteURL("https://example.com"));
    ASSERT_FALSE(IsAbsoluteURL("/path/to/page"));
    ASSERT_FALSE(IsAbsoluteURL("relative/path"));
    
    // GetBaseURL
    ASSERT_EQ(GetBaseURL("https://example.com/path/page.html"), "https://example.com");
    ASSERT_EQ(GetBaseURL("http://localhost:8080/api"), "http://localhost:8080");
    
    // ResolveURL
    ASSERT_EQ(ResolveURL("https://example.com/path/", "page.html"), 
              "https://example.com/path/page.html");
    ASSERT_EQ(ResolveURL("https://example.com/path/page.html", "/other.html"), 
              "https://example.com/other.html");
    ASSERT_EQ(ResolveURL("https://example.com/", "https://other.com/"), 
              "https://other.com/");
    
    // URLEncode/Decode
    ASSERT_EQ(URLEncode("hello world"), "hello%20world");
    ASSERT_EQ(URLDecode("hello%20world"), "hello world");
    
    // Trim
    ASSERT_EQ(Trim("  hello  "), "hello");
    ASSERT_EQ(Trim("\t\nhello\r\n"), "hello");
    
    // ToLower
    ASSERT_EQ(ToLower("HELLO World"), "hello world");
    
    // Split
    auto parts = Split("a,b,c", ',');
    ASSERT_EQ(parts.size(), 3);
    ASSERT_EQ(parts[0], "a");
    ASSERT_EQ(parts[1], "b");
    ASSERT_EQ(parts[2], "c");
}

// ============================================================================
// HTML Parser Tests
// ============================================================================

TEST(html_parser_basic) {
    HTMLParser parser;
    
    // Simple HTML
    std::string html = "<html><body><h1>Hello</h1></body></html>";
    auto doc = parser.Parse(html);
    
    ASSERT_NE(doc, nullptr);
    ASSERT_EQ(doc->type, NodeType::DOCUMENT);
    ASSERT_FALSE(doc->children.empty());
    
    // Extract text
    std::string text = parser.ExtractText(html);
    ASSERT_NE(text.find("Hello"), std::string::npos);
}

TEST(html_parser_attributes) {
    HTMLParser parser;
    
    std::string html = R"(<div id="main" class="container">
        <a href="https://example.com">Link</a>
    </div>)";
    
    auto doc = parser.Parse(html);
    ASSERT_NE(doc, nullptr);
    
    // Find div
    auto divs = doc->GetElementsByTagName("div");
    ASSERT_FALSE(divs.empty());
    
    auto div = divs[0];
    ASSERT_EQ(div->GetAttribute("id"), "main");
    ASSERT_EQ(div->GetAttribute("class"), "container");
}

TEST(html_parser_nested) {
    HTMLParser parser;
    
    std::string html = R"(<ul>
        <li>Item 1</li>
        <li>Item 2</li>
        <li>Item 3</li>
    </ul>)";
    
    auto doc = parser.Parse(html);
    ASSERT_NE(doc, nullptr);
    
    auto lists = doc->GetElementsByTagName("ul");
    ASSERT_FALSE(lists.empty());
    
    auto items = doc->GetElementsByTagName("li");
    ASSERT_EQ(items.size(), 3);
}

// ============================================================================
// DOM Tests
// ============================================================================

TEST(dom_node_creation) {
    auto node = std::make_shared<DOMNode>(NodeType::ELEMENT);
    node->tagName = "div";
    
    ASSERT_EQ(node->type, NodeType::ELEMENT);
    ASSERT_EQ(node->tagName, "div");
}

TEST(dom_attributes) {
    auto node = std::make_shared<DOMNode>(NodeType::ELEMENT);
    
    node->SetAttribute("id", "test");
    node->SetAttribute("class", "foo");
    node->SetAttribute("id", "updated"); // Update existing
    
    ASSERT_EQ(node->GetAttribute("id"), "updated");
    ASSERT_EQ(node->GetAttribute("class"), "foo");
    ASSERT_EQ(node->GetAttribute("missing"), "");
}

// ============================================================================
// Network Tests (may fail without internet)
// ============================================================================

TEST(network_init) {
    NetworkEngine network;
    ASSERT_TRUE(network.Initialize());
    network.Shutdown();
}

// ============================================================================
// Main Test Runner
// ============================================================================

int main() {
    std::cout << "======================================" << std::endl;
    std::cout << "RawrXD Browser Unit Tests" << std::endl;
    std::cout << "======================================" << std::endl;
    std::cout << std::endl;
    
    try {
        RUN_TEST(url_parsing);
        RUN_TEST(html_parser_basic);
        RUN_TEST(html_parser_attributes);
        RUN_TEST(html_parser_nested);
        RUN_TEST(dom_node_creation);
        RUN_TEST(dom_attributes);
        RUN_TEST(network_init);
        
        std::cout << std::endl;
        std::cout << "======================================" << std::endl;
        std::cout << "All tests PASSED!" << std::endl;
        std::cout << "======================================" << std::endl;
        
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Test FAILED with exception: " << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "Test FAILED with unknown exception" << std::endl;
        return 1;
    }
}
