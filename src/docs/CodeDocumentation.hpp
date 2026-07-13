/**
 * CodeDocumentation.hpp
 *
 * Phase J Batch 2/5: Code Documentation Generator
 *
 * Automatic code documentation generation from source code comments,
 * with support for multiple languages and output formats.
 */

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <optional>

namespace Docs {

// ============================================================================
// Forward Declarations
// ============================================================================

class CodeEntity;
class CodeNamespace;
class CodeClass;
class CodeFunction;
class CodeVariable;
class CodeEnum;
class CodeDocumentation;
class CodeDocGenerator;

// ============================================================================
// Source Language
// ============================================================================

enum class SourceLanguage {
    CPP,
    C,
    C_SHARP,
    JAVA,
    PYTHON,
    JAVASCRIPT,
    TYPESCRIPT,
    GO,
    RUST,
    SWIFT,
    KOTLIN,
    RUBY,
    PHP,
    OBJECTIVE_C,
    SCALA,
    DART,
    UNKNOWN
};

SourceLanguage DetectLanguage(const std::string& filename);
std::string LanguageToString(SourceLanguage lang);

// ============================================================================
// Access Modifier
// ============================================================================

enum class AccessModifier {
    PUBLIC,
    PROTECTED,
    PRIVATE,
    INTERNAL,
    PACKAGE_PRIVATE
};

// ============================================================================
// Entity Type
// ============================================================================

enum class EntityType {
    NAMESPACE,
    CLASS,
    STRUCT,
    INTERFACE,
    ENUM,
    FUNCTION,
    METHOD,
    CONSTRUCTOR,
    DESTRUCTOR,
    VARIABLE,
    FIELD,
    PROPERTY,
    CONSTANT,
    TYPEDEF,
    USING,
    TEMPLATE,
    MACRO,
    UNKNOWN
};

// ============================================================================
// Documentation Comment
// ============================================================================

/**
 * Parsed documentation comment.
 */
struct DocComment {
    std::string brief;              // Brief description
    std::string detailed;           // Detailed description
    std::vector<std::string> notes;
    std::vector<std::string> warnings;
    std::vector<std::string> examples;
    std::vector<std::string> seeAlso;
    std::optional<std::string> since;
    std::optional<std::string> deprecated;
    std::optional<std::string> version;
    std::optional<std::string> author;
    std::optional<std::string> copyright;
    std::optional<std::string> license;
    
    // Parameters
    struct ParamDoc {
        std::string name;
        std::string description;
        std::optional<std::string> type;
        bool optional;
        std::optional<std::string> defaultValue;
    };
    std::vector<ParamDoc> params;
    
    // Return value
    struct ReturnDoc {
        std::string description;
        std::optional<std::string> type;
    };
    std::optional<ReturnDoc> returnDoc;
    
    // Exceptions
    struct ExceptionDoc {
        std::string type;
        std::string description;
        std::string condition;
    };
    std::vector<ExceptionDoc> exceptions;
    
    // Template parameters
    struct TemplateParamDoc {
        std::string name;
        std::string description;
        std::optional<std::string> defaultValue;
    };
    std::vector<TemplateParamDoc> templateParams;
    
    // Code metadata
    std::map<std::string, std::string> tags;
    std::map<std::string, std::string> custom;
};

// ============================================================================
// Source Location
// ============================================================================

/**
 * Source code location.
 */
struct SourceLocation {
    std::string file;
    uint32_t line;
    uint32_t column;
    uint32_t endLine;
    uint32_t endColumn;
    
    SourceLocation() : line(0), column(0), endLine(0), endColumn(0) {}
    
    std::string ToString() const;
};

// ============================================================================
// Code Entity
// ============================================================================

/**
 * Base class for code entities.
 */
class CodeEntity {
public:
    CodeEntity(EntityType type, const std::string& name);
    virtual ~CodeEntity() = default;
    
    // Basic info
    EntityType GetType() const { return type_; }
    std::string GetName() const { return name_; }
    std::string GetFullName() const;
    
    // Documentation
    void SetDocComment(const DocComment& comment);
    const DocComment& GetDocComment() const { return docComment_; }
    bool HasDocumentation() const;
    
    // Location
    void SetLocation(const SourceLocation& loc);
    const SourceLocation& GetLocation() const { return location_; }
    
    // Access
    void SetAccess(AccessModifier access);
    AccessModifier GetAccess() const { return access_; }
    
    // Modifiers
    void SetStatic(bool isStatic);
    void SetConst(bool isConst);
    void SetVirtual(bool isVirtual);
    void SetAbstract(bool isAbstract);
    void SetFinal(bool isFinal);
    void SetOverride(bool isOverride);
    void SetInline(bool isInline);
    void SetExplicit(bool isExplicit);
    void SetNoexcept(bool isNoexcept);
    void SetDeprecated(bool isDeprecated, const std::string& reason = "");
    
    bool IsStatic() const { return modifiers_.static_; }
    bool IsConst() const { return modifiers_.const_; }
    bool IsVirtual() const { return modifiers_.virtual_; }
    bool IsAbstract() const { return modifiers_.abstract_; }
    bool IsFinal() const { return modifiers_.final_; }
    bool IsOverride() const { return modifiers_.override_; }
    bool IsInline() const { return modifiers_.inline_; }
    bool IsExplicit() const { return modifiers_.explicit_; }
    bool IsNoexcept() const { return modifiers_.noexcept_; }
    bool IsDeprecated() const { return modifiers_.deprecated_; }
    std::string GetDeprecationReason() const { return deprecationReason_; }
    
    // Parent
    void SetParent(std::shared_ptr<CodeEntity> parent);
    std::shared_ptr<CodeEntity> GetParent() const;
    
    // Children
    void AddChild(std::shared_ptr<CodeEntity> child);
    std::vector<std::shared_ptr<CodeEntity>> GetChildren() const;
    std::vector<std::shared_ptr<CodeEntity>> GetChildren(EntityType type) const;
    
    // Annotations
    void AddAnnotation(const std::string& name, const std::string& value = "");
    std::map<std::string, std::string> GetAnnotations() const;
    bool HasAnnotation(const std::string& name) const;
    std::optional<std::string> GetAnnotation(const std::string& name) const;
    
    // Export
    virtual std::string ToMarkdown() const = 0;
    virtual std::string ToHtml() const = 0;
    virtual std::string ToXml() const = 0;
    virtual std::string ToJson() const = 0;
    
protected:
    EntityType type_;
    std::string name_;
    DocComment docComment_;
    SourceLocation location_;
    AccessModifier access_;
    
    struct Modifiers {
        bool static_ = false;
        bool const_ = false;
        bool virtual_ = false;
        bool abstract_ = false;
        bool final_ = false;
        bool override_ = false;
        bool inline_ = false;
        bool explicit_ = false;
        bool noexcept_ = false;
        bool deprecated_ = false;
    } modifiers_;
    std::string deprecationReason_;
    
    std::weak_ptr<CodeEntity> parent_;
    std::vector<std::shared_ptr<CodeEntity>> children_;
    std::map<std::string, std::string> annotations_;
};

// ============================================================================
// Code Namespace
// ============================================================================

/**
 * Namespace or package.
 */
class CodeNamespace : public CodeEntity {
public:
    explicit CodeNamespace(const std::string& name);
    
    // Aliases
    void AddAlias(const std::string& alias, const std::string& target);
    std::map<std::string, std::string> GetAliases() const;
    
    // Export
    std::string ToMarkdown() const override;
    std::string ToHtml() const override;
    std::string ToXml() const override;
    std::string ToJson() const override;
    
private:
    std::map<std::string, std::string> aliases_;
};

// ============================================================================
// Code Type
// ============================================================================

/**
 * Type reference.
 */
struct TypeRef {
    std::string name;
    std::string fullName;
    bool isConst;
    bool isPointer;
    bool isReference;
    bool isArray;
    std::optional<uint32_t> arraySize;
    std::vector<TypeRef> templateArgs;
    std::optional<std::string> defaultValue;
};

// ============================================================================
// Code Variable
// ============================================================================

/**
 * Variable or field.
 */
class CodeVariable : public CodeEntity {
public:
    CodeVariable(const std::string& name, const TypeRef& type);
    
    // Type
    TypeRef GetType() const { return type_; }
    void SetType(const TypeRef& type);
    
    // Value
    void SetDefaultValue(const std::string& value);
    std::optional<std::string> GetDefaultValue() const;
    
    // Getter/Setter
    void SetGetter(const std::string& name);
    void SetSetter(const std::string& name);
    std::optional<std::string> GetGetter() const;
    std::optional<std::string> GetSetter() const;
    
    // Export
    std::string ToMarkdown() const override;
    std::string ToHtml() const override;
    std::string ToXml() const override;
    std::string ToJson() const override;
    
private:
    TypeRef type_;
    std::optional<std::string> defaultValue_;
    std::optional<std::string> getter_;
    std::optional<std::string> setter_;
};

// ============================================================================
// Code Function
// ============================================================================

/**
 * Function or method.
 */
class CodeFunction : public CodeEntity {
public:
    CodeFunction(const std::string& name, const TypeRef& returnType);
    
    // Parameters
    struct Parameter {
        std::string name;
        TypeRef type;
        std::optional<std::string> defaultValue;
        bool isOutput;
        bool isVariadic;
    };
    
    void AddParameter(const Parameter& param);
    std::vector<Parameter> GetParameters() const;
    
    // Return type
    TypeRef GetReturnType() const { return returnType_; }
    void SetReturnType(const TypeRef& type);
    
    // Template parameters
    void AddTemplateParam(const std::string& name, const std::string& description = "");
    std::vector<std::string> GetTemplateParams() const;
    
    // Overloads
    void AddOverload(std::shared_ptr<CodeFunction> overload);
    std::vector<std::shared_ptr<CodeFunction>> GetOverloads() const;
    
    // Body
    void SetBody(const std::string& body);
    std::optional<std::string> GetBody() const;
    
    // Export
    std::string ToMarkdown() const override;
    std::string ToHtml() const override;
    std::string ToXml() const override;
    std::string ToJson() const override;
    
private:
    TypeRef returnType_;
    std::vector<Parameter> parameters_;
    std::vector<std::string> templateParams_;
    std::vector<std::shared_ptr<CodeFunction>> overloads_;
    std::optional<std::string> body_;
};

// ============================================================================
// Code Class
// ============================================================================

/**
 * Class, struct, or interface.
 */
class CodeClass : public CodeEntity {
public:
    enum class Type {
        CLASS,
        STRUCT,
        INTERFACE,
        UNION,
        ENUM_CLASS
    };
    
    CodeClass(const std::string& name, Type type = Type::CLASS);
    
    // Type
    Type GetClassType() const { return classType_; }
    
    // Inheritance
    struct BaseClass {
        std::string name;
        AccessModifier access;
        bool isVirtual;
    };
    
    void AddBaseClass(const BaseClass& base);
    std::vector<BaseClass> GetBaseClasses() const;
    
    // Template
    void SetTemplate(bool isTemplate);
    bool IsTemplate() const;
    void AddTemplateParam(const std::string& name, const std::string& description = "");
    std::vector<std::string> GetTemplateParams() const;
    
    // Members
    std::vector<std::shared_ptr<CodeVariable>> GetFields() const;
    std::vector<std::shared_ptr<CodeFunction>> GetMethods() const;
    std::vector<std::shared_ptr<CodeFunction>> GetConstructors() const;
    std::vector<std::shared_ptr<CodeFunction>> GetDestructors() const;
    std::vector<std::shared_ptr<CodeClass>> GetNestedClasses() const;
    
    // Friends
    void AddFriend(const std::string& name);
    std::vector<std::string> GetFriends() const;
    
    // Export
    std::string ToMarkdown() const override;
    std::string ToHtml() const override;
    std::string ToXml() const override;
    std::string ToJson() const override;
    
private:
    Type classType_;
    std::vector<BaseClass> baseClasses_;
    bool isTemplate_ = false;
    std::vector<std::string> templateParams_;
    std::vector<std::string> friends_;
};

// ============================================================================
// Code Enum
// ============================================================================

/**
 * Enumeration.
 */
class CodeEnum : public CodeEntity {
public:
    explicit CodeEnum(const std::string& name);
    
    // Values
    struct EnumValue {
        std::string name;
        std::optional<int64_t> value;
        DocComment doc;
        bool isDeprecated;
    };
    
    void AddValue(const EnumValue& value);
    std::vector<EnumValue> GetValues() const;
    
    // Underlying type
    void SetUnderlyingType(const std::string& type);
    std::string GetUnderlyingType() const;
    
    // Scoped (enum class)
    void SetScoped(bool scoped);
    bool IsScoped() const;
    
    // Export
    std::string ToMarkdown() const override;
    std::string ToHtml() const override;
    std::string ToXml() const override;
    std::string ToJson() const override;
    
private:
    std::vector<EnumValue> values_;
    std::string underlyingType_ = "int";
    bool scoped_ = false;
};

// ============================================================================
// Code Macro
// ============================================================================

/**
 * Preprocessor macro.
 */
class CodeMacro : public CodeEntity {
public:
    explicit CodeMacro(const std::string& name);
    
    // Parameters
    void AddParameter(const std::string& param);
    std::vector<std::string> GetParameters() const;
    bool IsFunctionLike() const;
    
    // Definition
    void SetDefinition(const std::string& definition);
    std::string GetDefinition() const;
    
    // Export
    std::string ToMarkdown() const override;
    std::string ToHtml() const override;
    std::string ToXml() const override;
    std::string ToJson() const override;
    
private:
    std::vector<std::string> parameters_;
    std::string definition_;
};

// ============================================================================
// Code Documentation
// ============================================================================

/**
 * Complete code documentation.
 */
class CodeDocumentation {
public:
    struct Config {
        std::string projectName;
        std::string projectVersion;
        std::string projectDescription;
        std::string outputDirectory;
        std::vector<std::string> sourcePaths;
        std::vector<std::string> excludePatterns;
        std::vector<std::string> fileExtensions;
    };
    
    explicit CodeDocumentation(const Config& config);
    
    // Namespaces
    void AddNamespace(std::shared_ptr<CodeNamespace> ns);
    std::vector<std::shared_ptr<CodeNamespace>> GetNamespaces() const;
    std::shared_ptr<CodeNamespace> GetNamespace(const std::string& name) const;
    std::shared_ptr<CodeNamespace> GetGlobalNamespace() const;
    
    // Classes
    void AddClass(std::shared_ptr<CodeClass> cls);
    std::vector<std::shared_ptr<CodeClass>> GetClasses() const;
    std::shared_ptr<CodeClass> GetClass(const std::string& name) const;
    
    // Functions
    void AddFunction(std::shared_ptr<CodeFunction> func);
    std::vector<std::shared_ptr<CodeFunction>> GetFunctions() const;
    std::vector<std::shared_ptr<CodeFunction>> GetFunctions(const std::string& namespaceName) const;
    
    // Enums
    void AddEnum(std::shared_ptr<CodeEnum> enm);
    std::vector<std::shared_ptr<CodeEnum>> GetEnums() const;
    
    // Macros
    void AddMacro(std::shared_ptr<CodeMacro> macro);
    std::vector<std::shared_ptr<CodeMacro>> GetMacros() const;
    
    // Search
    std::vector<std::shared_ptr<CodeEntity>> Search(const std::string& query) const;
    std::vector<std::shared_ptr<CodeEntity>> SearchByTag(const std::string& tag) const;
    std::vector<std::shared_ptr<CodeEntity>> GetUndocumented() const;
    std::vector<std::shared_ptr<CodeEntity>> GetDeprecated() const;
    
    // Statistics
    struct Stats {
        uint32_t totalFiles;
        uint32_t totalLines;
        uint32_t totalEntities;
        uint32_t documentedEntities;
        uint32_t undocumentedEntities;
        uint32_t deprecatedEntities;
        double documentationCoverage;
    };
    Stats GetStats() const;
    
    // Export
    bool GenerateMarkdown(const std::string& outputPath);
    bool GenerateHtml(const std::string& outputPath);
    bool GenerateXml(const std::string& outputPath);
    bool GenerateJson(const std::string& outputPath);
    bool GenerateManPages(const std::string& outputPath);
    bool GenerateQtHelp(const std::string& outputPath);
    
private:
    Config config_;
    std::vector<std::shared_ptr<CodeNamespace>> namespaces_;
    std::vector<std::shared_ptr<CodeClass>> classes_;
    std::vector<std::shared_ptr<CodeFunction>> functions_;
    std::vector<std::shared_ptr<CodeEnum>> enums_;
    std::vector<std::shared_ptr<CodeMacro>> macros_;
    
    std::shared_ptr<CodeNamespace> globalNamespace_;
};

// ============================================================================
// Code Doc Generator
// ============================================================================

/**
 * Generates code documentation from source files.
 */
class CodeDocGenerator {
public:
    struct Config {
        std::string projectName;
        std::string projectVersion;
        std::vector<std::string> inputPaths;
        std::string outputPath;
        std::string outputFormat = "html";  // html, markdown, xml, json
        std::vector<std::string> excludePatterns;
        bool recursive = true;
        bool includePrivate = false;
        bool includeProtected = true;
        bool extractCode = false;
        std::string templatePath;
        std::string cssPath;
    };
    
    explicit CodeDocGenerator(const Config& config);
    
    // Parsing
    bool Parse();
    bool ParseFile(const std::string& filepath);
    bool ParseDirectory(const std::string& dirpath);
    
    // Generation
    bool Generate();
    bool GenerateMarkdown();
    bool GenerateHtml();
    bool GenerateXml();
    bool GenerateJson();
    bool GenerateManPages();
    
    // Access
    std::shared_ptr<CodeDocumentation> GetDocumentation() const;
    
    // Cross-references
    void ResolveCrossReferences();
    void GenerateInheritanceGraphs();
    void GenerateCallGraphs();
    
    // Statistics
    CodeDocumentation::Stats GetStats() const;
    
private:
    Config config_;
    std::shared_ptr<CodeDocumentation> documentation_;
    
    std::shared_ptr<CodeEntity> ParseEntity(const std::string& code, SourceLanguage lang);
    DocComment ParseDocComment(const std::string& comment, SourceLanguage lang);
    std::string ExtractBrief(const std::string& detailed);
};

// ============================================================================
// Comment Parser
// ============================================================================

/**
 * Parses documentation comments from source code.
 */
class CommentParser {
public:
    explicit CommentParser(SourceLanguage lang);
    
    // Parse
    DocComment Parse(const std::string& comment);
    
    // Extract from source
    std::vector<std::pair<SourceLocation, DocComment>> ExtractFromFile(
        const std::string& filepath);
    
    // Language-specific
    static std::string ExtractJavadoc(const std::string& comment);
    static std::string ExtractDoxygen(const std::string& comment);
    static std::string ExtractXmlDoc(const std::string& comment);
    static std::string ExtractPythonDocstring(const std::string& comment);
    static std::string ExtractRustDoc(const std::string& comment);
    
private:
    SourceLanguage language_;
    
    void ParseParam(const std::string& line, DocComment& doc);
    void ParseReturn(const std::string& line, DocComment& doc);
    void ParseException(const std::string& line, DocComment& doc);
    void ParseTemplateParam(const std::string& line, DocComment& doc);
    void ParseTag(const std::string& line, DocComment& doc);
};

// ============================================================================
// Template Engine
// ============================================================================

/**
 * Template engine for documentation generation.
 */
class DocTemplateEngine {
public:
    explicit DocTemplateEngine(const std::string& templateDir);
    
    // Templates
    void LoadTemplate(const std::string& name, const std::string& filepath);
    void SetTemplate(const std::string& name, const std::string& content);
    
    // Rendering
    std::string Render(const std::string& templateName,
                       const std::map<std::string, std::string>& variables);
    std::string RenderEntity(std::shared_ptr<CodeEntity> entity);
    std::string RenderIndex(const std::vector<std::shared_ptr<CodeEntity>>& entities);
    std::string RenderSearchPage();
    
    // Built-in templates
    static std::string GetDefaultHtmlTemplate();
    static std::string GetDefaultMarkdownTemplate();
    static std::string GetDefaultXmlTemplate();
    
private:
    std::string templateDir_;
    std::map<std::string, std::string> templates_;
    
    std::string ProcessTemplate(const std::string& templateStr,
                                 const std::map<std::string, std::string>& variables);
};

} // namespace Docs
