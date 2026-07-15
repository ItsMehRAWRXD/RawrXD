//=============================================================================
// config_manager.c - Configuration Manager
// Production-ready configuration file parsing and management
//=============================================================================

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>

//=============================================================================
// Configuration Types
//=============================================================================

#define MAX_CONFIG_KEYS 1024
#define MAX_KEY_LENGTH 256
#define MAX_VALUE_LENGTH 4096

typedef enum {
    CONFIG_TYPE_STRING,
    CONFIG_TYPE_INT,
    CONFIG_TYPE_FLOAT,
    CONFIG_TYPE_BOOL,
    CONFIG_TYPE_ARRAY
} ConfigValueType;

typedef struct {
    char key[MAX_KEY_LENGTH];
    char value[MAX_VALUE_LENGTH];
    ConfigValueType type;
    
    union {
        int int_val;
        double float_val;
        int bool_val;
    } data;
} ConfigEntry;

typedef struct {
    ConfigEntry* entries;
    int entry_count;
    int entry_capacity;
    char filename[512];
    int modified;
} Config;

//=============================================================================
// Configuration Lifecycle
//=============================================================================

Config* config_create(void) {
    Config* cfg = (Config*)calloc(1, sizeof(Config));
    cfg->entry_capacity = MAX_CONFIG_KEYS;
    cfg->entries = (ConfigEntry*)calloc(cfg->entry_capacity, sizeof(ConfigEntry));
    return cfg;
}

void config_destroy(Config* cfg) {
    if (!cfg) return;
    
    // Save if modified
    if (cfg->modified && strlen(cfg->filename) > 0) {
        config_save(cfg, cfg->filename);
    }
    
    free(cfg->entries);
    free(cfg);
}

//=============================================================================
// Configuration Parsing
//=============================================================================

char* trim_whitespace(char* str) {
    while (isspace((unsigned char)*str)) str++;
    if (*str == 0) return str;
    
    char* end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    end[1] = '\0';
    
    return str;
}

int parse_value_type(const char* value) {
    // Check for boolean
    if (strcmp(value, "true") == 0 || strcmp(value, "false") == 0 ||
        strcmp(value, "yes") == 0 || strcmp(value, "no") == 0 ||
        strcmp(value, "1") == 0 || strcmp(value, "0") == 0) {
        return CONFIG_TYPE_BOOL;
    }
    
    // Check for integer
    char* endptr;
    long int_val = strtol(value, &endptr, 10);
    if (*endptr == '\0') {
        return CONFIG_TYPE_INT;
    }
    
    // Check for float
    double float_val = strtod(value, &endptr);
    if (*endptr == '\0') {
        return CONFIG_TYPE_FLOAT;
    }
    
    // Check for array (comma-separated)
    if (strchr(value, ',')) {
        return CONFIG_TYPE_ARRAY;
    }
    
    return CONFIG_TYPE_STRING;
}

int config_load(Config* cfg, const char* filename) {
    FILE* f = fopen(filename, "r");
    if (!f) return -1;
    
    strncpy(cfg->filename, filename, sizeof(cfg->filename) - 1);
    
    char line[MAX_VALUE_LENGTH];
    int line_num = 0;
    
    while (fgets(line, sizeof(line), f)) {
        line_num++;
        
        // Remove newline
        size_t len = strlen(line);
        if (len > 0 && line[len-1] == '\n') {
            line[len-1] = '\0';
        }
        
        // Skip empty lines and comments
        char* trimmed = trim_whitespace(line);
        if (strlen(trimmed) == 0 || trimmed[0] == '#' || trimmed[0] == ';') {
            continue;
        }
        
        // Parse key=value
        char* equals = strchr(trimmed, '=');
        if (!equals) continue;
        
        *equals = '\0';
        char* key = trim_whitespace(trimmed);
        char* value = trim_whitespace(equals + 1);
        
        // Remove quotes if present
        if (value[0] == '"' || value[0] == '\'') {
            size_t val_len = strlen(value);
            if (val_len >= 2 && value[val_len-1] == value[0]) {
                value[val_len-1] = '\0';
                value++;
            }
        }
        
        // Add to config
        config_set_string(cfg, key, value);
    }
    
    fclose(f);
    cfg->modified = 0;
    
    return 0;
}

int config_save(Config* cfg, const char* filename) {
    FILE* f = fopen(filename, "w");
    if (!f) return -1;
    
    fprintf(f, "# RawrXD Configuration File\n");
    fprintf(f, "# Generated: %s\n", __DATE__);
    fprintf(f, "\n");
    
    for (int i = 0; i < cfg->entry_count; i++) {
        ConfigEntry* entry = &cfg->entries[i];
        fprintf(f, "%s=%s\n", entry->key, entry->value);
    }
    
    fclose(f);
    cfg->modified = 0;
    
    return 0;
}

//=============================================================================
// Configuration Accessors
//=============================================================================

ConfigEntry* find_entry(Config* cfg, const char* key) {
    for (int i = 0; i < cfg->entry_count; i++) {
        if (strcmp(cfg->entries[i].key, key) == 0) {
            return &cfg->entries[i];
        }
    }
    return NULL;
}

void config_set_string(Config* cfg, const char* key, const char* value) {
    ConfigEntry* entry = find_entry(cfg, key);
    
    if (!entry) {
        if (cfg->entry_count >= cfg->entry_capacity) return;
        entry = &cfg->entries[cfg->entry_count++];
        strncpy(entry->key, key, sizeof(entry->key) - 1);
    }
    
    strncpy(entry->value, value, sizeof(entry->value) - 1);
    entry->type = CONFIG_TYPE_STRING;
    cfg->modified = 1;
}

void config_set_int(Config* cfg, const char* key, int value) {
    char str_val[32];
    snprintf(str_val, sizeof(str_val), "%d", value);
    config_set_string(cfg, key, str_val);
    
    ConfigEntry* entry = find_entry(cfg, key);
    if (entry) {
        entry->type = CONFIG_TYPE_INT;
        entry->data.int_val = value;
    }
}

void config_set_float(Config* cfg, const char* key, double value) {
    char str_val[64];
    snprintf(str_val, sizeof(str_val), "%f", value);
    config_set_string(cfg, key, str_val);
    
    ConfigEntry* entry = find_entry(cfg, key);
    if (entry) {
        entry->type = CONFIG_TYPE_FLOAT;
        entry->data.float_val = value;
    }
}

void config_set_bool(Config* cfg, const char* key, int value) {
    config_set_string(cfg, key, value ? "true" : "false");
    
    ConfigEntry* entry = find_entry(cfg, key);
    if (entry) {
        entry->type = CONFIG_TYPE_BOOL;
        entry->data.bool_val = value;
    }
}

const char* config_get_string(Config* cfg, const char* key, const char* default_val) {
    ConfigEntry* entry = find_entry(cfg, key);
    return entry ? entry->value : default_val;
}

int config_get_int(Config* cfg, const char* key, int default_val) {
    ConfigEntry* entry = find_entry(cfg, key);
    if (!entry) return default_val;
    
    if (entry->type == CONFIG_TYPE_INT) {
        return entry->data.int_val;
    }
    
    return atoi(entry->value);
}

double config_get_float(Config* cfg, const char* key, double default_val) {
    ConfigEntry* entry = find_entry(cfg, key);
    if (!entry) return default_val;
    
    if (entry->type == CONFIG_TYPE_FLOAT) {
        return entry->data.float_val;
    }
    
    return atof(entry->value);
}

int config_get_bool(Config* cfg, const char* key, int default_val) {
    ConfigEntry* entry = find_entry(cfg, key);
    if (!entry) return default_val;
    
    if (entry->type == CONFIG_TYPE_BOOL) {
        return entry->data.bool_val;
    }
    
    return (strcmp(entry->value, "true") == 0 ||
            strcmp(entry->value, "yes") == 0 ||
            strcmp(entry->value, "1") == 0);
}

int config_has_key(Config* cfg, const char* key) {
    return find_entry(cfg, key) != NULL;
}

void config_remove(Config* cfg, const char* key) {
    for (int i = 0; i < cfg->entry_count; i++) {
        if (strcmp(cfg->entries[i].key, key) == 0) {
            // Shift remaining entries
            for (int j = i; j < cfg->entry_count - 1; j++) {
                cfg->entries[j] = cfg->entries[j + 1];
            }
            cfg->entry_count--;
            cfg->modified = 1;
            return;
        }
    }
}

//=============================================================================
// Configuration Display
//=============================================================================

void config_print(Config* cfg) {
    printf("Configuration (%d entries):\n", cfg->entry_count);
    printf("%-30s %-10s %s\n", "Key", "Type", "Value");
    printf("---------------------------------------------------------------------\n");
    
    for (int i = 0; i < cfg->entry_count; i++) {
        ConfigEntry* entry = &cfg->entries[i];
        const char* type_str = "string";
        
        switch (entry->type) {
            case CONFIG_TYPE_INT: type_str = "int"; break;
            case CONFIG_TYPE_FLOAT: type_str = "float"; break;
            case CONFIG_TYPE_BOOL: type_str = "bool"; break;
            case CONFIG_TYPE_ARRAY: type_str = "array"; break;
            default: type_str = "string"; break;
        }
        
        printf("%-30s %-10s %s\n", entry->key, type_str, entry->value);
    }
}

//=============================================================================
// Main Entry Point
//=============================================================================

int main(int argc, char* argv[]) {
    printf("RawrXD Configuration Manager\n");
    printf("============================\n\n");
    
    Config* cfg = config_create();
    
    // Set some default values
    config_set_string(cfg, "build.output_dir", "build");
    config_set_int(cfg, "build.parallel_jobs", 4);
    config_set_bool(cfg, "build.verbose", 1);
    config_set_float(cfg, "test.timeout_seconds", 30.0);
    config_set_string(cfg, "test.filter", "*");
    config_set_bool(cfg, "coverage.enabled", 1);
    config_set_string(cfg, "coverage.format", "html");
    
    printf("Default configuration:\n");
    config_print(cfg);
    
    // Save to file
    printf("\nSaving to config.txt...\n");
    if (config_save(cfg, "config.txt") == 0) {
        printf("  ✓ Configuration saved\n");
    } else {
        printf("  ✗ Failed to save\n");
    }
    
    // Load from file
    printf("\nLoading from config.txt...\n");
    Config* cfg2 = config_create();
    if (config_load(cfg2, "config.txt") == 0) {
        printf("  ✓ Configuration loaded\n\n");
        config_print(cfg2);
    } else {
        printf("  ✗ Failed to load\n");
    }
    
    // Cleanup
    config_destroy(cfg);
    config_destroy(cfg2);
    
    return 0;
}
