# Batch 27 - Resource Analyzer
## Sovereign IDE Subsystem Documentation

**Version:** 1.0.0
**Date:** 2026-07-11
**Status:** ✅ Complete

---

## Overview

The Resource Analyzer analyzes binary resources such as icons, manifests, certificates, and embedded data. It provides resource enumeration, manifest parsing, certificate extraction, and embedded data analysis.

### Key Characteristics

| Attribute | Value |
|-----------|-------|
| **Language** | C++17 |
| **Lines of Code** | ~4,500 |
| **Resource Types** | 20+ |
| **Formats** | PE Resources, ELF Sections, Mach-O Bundles |
| **SEG Nodes** | 1 |
| **MoE Experts** | 1 |

---

## Responsibilities

1. **Resource Enumeration** - List all resources in binary
2. **Manifest Parsing** - Parse application manifests
3. **Certificate Extraction** - Extract embedded certificates
4. **Embedded Data Analysis** - Analyze embedded files
5. **Version Info Extraction** - Extract version information

---

## Architecture

```
┌─────────────────────────────────────────────┐
│           Resource Analyzer                 │
├─────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────────┐    │
│  │   Resource   │  │   Manifest       │    │
│  │   Enumerator │  │   Parser         │    │
│  └──────────────┘  └──────────────────┘    │
│  ┌──────────────┐  ┌──────────────────┐    │
│  │   Certificate│  │   Embedded       │    │
│  │   Extractor  │  │   Data Analyzer    │    │
│  └──────────────┘  └──────────────────┘    │
└─────────────────────────────────────────────┘
```

---

## ABI Surfaces

```cpp
// Resource analyzer initialization
SOVEREIGN_API ResourceResult Resource_Initialize();
SOVEREIGN_API void Resource_Shutdown();

// Resource enumeration
SOVEREIGN_API ResourceResult Resource_Enumerate(BinaryHandle binary,
                                               ResourceList** resources);
SOVEREIGN_API size_t Resource_GetCount(ResourceList* resources);
SOVEREIGN_API Resource* Resource_GetItem(ResourceList* resources, size_t index);

// Resource access
SOVEREIGN_API const char* Resource_GetName(Resource* resource);
SOVEREIGN_API ResourceType Resource_GetType(Resource* resource);
SOVEREIGN_API const void* Resource_GetData(Resource* resource);
SOVEREIGN_API size_t Resource_GetSize(Resource* resource);

// Specific resource types
SOVEREIGN_API Manifest* Resource_ParseManifest(Resource* resource);
SOVEREIGN_API Certificate* Resource_ExtractCertificate(Resource* resource);
SOVEREIGN_API VersionInfo* Resource_ParseVersionInfo(Resource* resource);
```

---

## SEG Nodes

| Node ID | Name | Type | Description |
|---------|------|------|-------------|
| 0x001F | `SEGNode_AnalyzeResources` | Analysis | Analyze binary resources |

---

## MoE Experts

| Expert Name | Domain | Description |
|-------------|--------|-------------|
| `Expert_ResourceInference` | resources | Infer resource significance |

---

## Implementation Details

### PE Resource Analyzer

```cpp
class PEResourceAnalyzer {
public:
    ResourceList Analyze(const PEBinary& binary) {
        ResourceList resources;
        
        // Get resource directory
        auto resourceDir = binary.GetResourceDirectory();
        if (!resourceDir) {
            return resources;
        }
        
        // Enumerate resource types
        EnumerateResources(resourceDir, resources);
        
        return resources;
    }
    
private:
    void EnumerateResources(const ResourceDirectory* dir,
                           ResourceList& resources,
                           const std::string& path = "") {
        for (const auto& entry : dir->entries) {
            std::string entryPath = path;
            if (!entryPath.empty()) entryPath += "/";
            
            if (entry.isNamed) {
                entryPath += entry.name;
            } else {
                entryPath += std::to_string(entry.id);
            }
            
            if (entry.isDirectory) {
                // Recurse into subdirectory
                EnumerateResources(entry.subdirectory, resources, entryPath);
            } else {
                // Leaf node - actual resource
                Resource resource;
                resource.name = entryPath;
                resource.type = GetResourceType(entry.id);
                resource.data = entry.data;
                resource.size = entry.size;
                resources.push_back(resource);
            }
        }
    }
    
    ResourceType GetResourceType(uint32_t id) {
        switch (id) {
            case RT_CURSOR:       return RESOURCE_CURSOR;
            case RT_BITMAP:       return RESOURCE_BITMAP;
            case RT_ICON:         return RESOURCE_ICON;
            case RT_MENU:         return RESOURCE_MENU;
            case RT_DIALOG:       return RESOURCE_DIALOG;
            case RT_STRING:       return RESOURCE_STRING;
            case RT_FONTDIR:      return RESOURCE_FONTDIR;
            case RT_FONT:         return RESOURCE_FONT;
            case RT_ACCELERATOR:  return RESOURCE_ACCELERATOR;
            case RT_RCDATA:       return RESOURCE_RCDATA;
            case RT_MESSAGETABLE: return RESOURCE_MESSAGETABLE;
            case RT_GROUP_CURSOR: return RESOURCE_GROUP_CURSOR;
            case RT_GROUP_ICON:   return RESOURCE_GROUP_ICON;
            case RT_VERSION:      return RESOURCE_VERSION;
            case RT_DLGINCLUDE:   return RESOURCE_DLGINCLUDE;
            case RT_PLUGPLAY:     return RESOURCE_PLUGPLAY;
            case RT_VXD:          return RESOURCE_VXD;
            case RT_ANICURSOR:    return RESOURCE_ANICURSOR;
            case RT_ANIICON:      return RESOURCE_ANIICON;
            case RT_HTML:         return RESOURCE_HTML;
            case RT_MANIFEST:     return RESOURCE_MANIFEST;
            default:              return RESOURCE_UNKNOWN;
        }
    }
};
```

### Manifest Parser

```cpp
class ManifestParser {
public:
    Manifest Parse(const Resource& resource) {
        Manifest manifest;
        
        // Parse XML
        auto xml = ParseXML(resource.data, resource.size);
        
        // Extract assembly info
        auto assembly = xml.FindElement("assembly");
        if (assembly) {
            manifest.identity.name = assembly.GetAttribute("name");
            manifest.identity.version = assembly.GetAttribute("version");
            manifest.identity.architecture = assembly.GetAttribute("processorArchitecture");
        }
        
        // Extract dependencies
        auto dependencies = xml.FindElements("dependency");
        for (const auto& dep : dependencies) {
            Dependency dependency;
            dependency.name = dep.GetAttribute("name");
            dependency.version = dep.GetAttribute("version");
            manifest.dependencies.push_back(dependency);
        }
        
        // Extract requested privileges
        auto security = xml.FindElement("security");
        if (security) {
            auto privileges = security.FindElement("requestedPrivileges");
            if (privileges) {
                manifest.executionLevel = privileges.GetAttribute("level");
                manifest.uiAccess = privileges.GetAttribute("uiAccess") == "true";
            }
        }
        
        return manifest;
    }
};
```

---

## Testing

```cpp
TEST(ResourceAnalyzer, EnumerateResources) {
    Resource_Initialize();
    
    // Load binary with resources
    auto binary = Loader_Load("test_with_resources.exe");
    
    // Enumerate resources
    ResourceList* resources;
    auto result = Resource_Enumerate(binary, &resources);
    EXPECT_EQ(result, RESOURCE_SUCCESS);
    EXPECT_GT(Resource_GetCount(resources), 0);
    
    // Check for expected resources
    bool foundIcon = false;
    bool foundManifest = false;
    
    for (size_t i = 0; i < Resource_GetCount(resources); ++i) {
        auto resource = Resource_GetItem(resources, i);
        if (Resource_GetType(resource) == RESOURCE_ICON) {
            foundIcon = true;
        }
        if (Resource_GetType(resource) == RESOURCE_MANIFEST) {
            foundManifest = true;
        }
    }
    
    EXPECT_TRUE(foundIcon);
    EXPECT_TRUE(foundManifest);
    
    Resource_Shutdown();
}

TEST(ResourceAnalyzer, ParseManifest) {
    Resource_Initialize();
    
    // Load binary with manifest
    auto binary = Loader_Load("test_with_manifest.exe");
    
    ResourceList* resources;
    Resource_Enumerate(binary, &resources);
    
    // Find manifest resource
    for (size_t i = 0; i < Resource_GetCount(resources); ++i) {
        auto resource = Resource_GetItem(resources, i);
        if (Resource_GetType(resource) == RESOURCE_MANIFEST) {
            auto manifest = Resource_ParseManifest(resource);
            EXPECT_NE(manifest, nullptr);
            EXPECT_FALSE(manifest->identity.name.empty());
        }
    }
    
    Resource_Shutdown();
}
```

---

## Summary

Batch 27 - Resource Analyzer provides:

- ✅ **Resource enumeration**
- ✅ **Manifest parsing**
- ✅ **Certificate extraction**
- ✅ **Embedded data analysis**
- ✅ **Version info extraction**

**Status:** ✅ Complete
