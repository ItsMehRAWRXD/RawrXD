//=============================================================================
// test_data_generator.c - Test Data Generator
// Production-ready test data generation with various strategies
//=============================================================================

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <math.h>

//=============================================================================
// Test Data Types
//=============================================================================

#define MAX_GENERATORS 50
#define MAX_DATASETS 100
#define MAX_RECORD_SIZE 4096

typedef enum {
    GEN_INTEGER,
    GEN_FLOAT,
    GEN_STRING,
    GEN_BOOLEAN,
    GEN_DATE,
    GEN_EMAIL,
    GEN_UUID,
    GEN_NAME,
    GEN_ADDRESS,
    GEN_PHONE,
    GEN_URL,
    GEN_IP_ADDRESS,
    GEN_CREDIT_CARD,
    GEN_SSN,
    GEN_ENUM
} GeneratorType;

typedef enum {
    DIST_UNIFORM,
    DIST_NORMAL,
    DIST_EXPONENTIAL,
    DIST_ZIPF
} DistributionType;

typedef struct {
    char name[128];
    GeneratorType type;
    DistributionType distribution;
    
    // Range constraints
    double min_value;
    double max_value;
    int nullable;
    double null_probability;
    
    // String constraints
    int min_length;
    int max_length;
    char charset[256];
    char prefix[64];
    char suffix[64];
    
    // Enum values
    char enum_values[20][128];
    int enum_count;
    
    // Distribution parameters
    double mean;
    double stddev;
    double lambda;
    
    int unique;
    int seed;
} DataGenerator;

typedef struct {
    char name[256];
    char** columns;
    int column_count;
    int column_capacity;
    
    char*** data;
    int row_count;
    int row_capacity;
    
    char format[32];  // csv, json, sql, xml
    char output_file[512];
} DataSet;

typedef struct {
    DataGenerator* generators;
    int generator_count;
    int generator_capacity;
    
    DataSet* datasets;
    int dataset_count;
    int dataset_capacity;
    
    int total_records;
    int total_bytes;
    double generation_time_ms;
} TestDataReport;

//=============================================================================
// Random Number Generation
//=============================================================================

static uint32_t rng_state = 12345;

void seed_random(int seed) {
    rng_state = seed > 0 ? (uint32_t)seed : (uint32_t)time(NULL);
    srand(rng_state);
}

uint32_t random_int(void) {
    rng_state = rng_state * 1103515245 + 12345;
    return rng_state;
}

double random_double(void) {
    return (double)random_int() / 4294967296.0;
}

double random_normal(double mean, double stddev) {
    // Box-Muller transform
    static int has_spare = 0;
    static double spare;
    
    if (has_spare) {
        has_spare = 0;
        return mean + stddev * spare;
    }
    
    has_spare = 1;
    double u1 = random_double();
    double u2 = random_double();
    double mag = stddev * sqrt(-2.0 * log(u1));
    double z0 = mag * cos(2.0 * M_PI * u2);
    spare = mag * sin(2.0 * M_PI * u2);
    
    return mean + z0;
}

int random_range(int min, int max) {
    return min + (int)(random_double() * (max - min + 1));
}

//=============================================================================
// Data Generators
//=============================================================================

const char* first_names[] = {
    "James", "Mary", "John", "Patricia", "Robert", "Jennifer", "Michael", "Linda",
    "William", "Elizabeth", "David", "Barbara", "Richard", "Susan", "Joseph", "Jessica",
    "Thomas", "Sarah", "Charles", "Karen", "Christopher", "Nancy", "Daniel", "Lisa"
};

const char* last_names[] = {
    "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis",
    "Rodriguez", "Martinez", "Hernandez", "Lopez", "Gonzalez", "Wilson", "Anderson", "Thomas"
};

const char* domains[] = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "example.com",
    "company.com", "enterprise.org", "business.net"
};

const char* streets[] = {
    "Main St", "Oak Ave", "Park Rd", "Elm St", "Maple Dr", "Washington Ave",
    "Lake St", "Forest Dr", "River Rd", "Hill Ave"
};

const char* cities[] = {
    "New York", "Los Angeles", "Chicago", "Houston", "Phoenix", "Philadelphia",
    "San Antonio", "San Diego", "Dallas", "San Jose"
};

const char* states[] = {
    "CA", "TX", "FL", "NY", "PA", "IL", "OH", "GA", "NC", "MI"
};

void generate_integer(char* output, size_t size, DataGenerator* gen) {
    if (gen->nullable && random_double() < gen->null_probability) {
        strncpy(output, "NULL", size);
        return;
    }
    
    int value;
    switch (gen->distribution) {
        case DIST_NORMAL:
            value = (int)random_normal(gen->mean, gen->stddev);
            break;
        case DIST_UNIFORM:
        default:
            value = random_range((int)gen->min_value, (int)gen->max_value);
            break;
    }
    
    snprintf(output, size, "%d", value);
}

void generate_float(char* output, size_t size, DataGenerator* gen) {
    if (gen->nullable && random_double() < gen->null_probability) {
        strncpy(output, "NULL", size);
        return;
    }
    
    double value;
    switch (gen->distribution) {
        case DIST_NORMAL:
            value = random_normal(gen->mean, gen->stddev);
            break;
        case DIST_EXPONENTIAL:
            value = -log(1.0 - random_double()) / gen->lambda;
            break;
        default:
            value = gen->min_value + random_double() * (gen->max_value - gen->min_value);
            break;
    }
    
    snprintf(output, size, "%.4f", value);
}

void generate_string(char* output, size_t size, DataGenerator* gen) {
    if (gen->nullable && random_double() < gen->null_probability) {
        strncpy(output, "NULL", size);
        return;
    }
    
    int length = random_range(gen->min_length, gen->max_length);
    if (length >= (int)size) length = size - 1;
    
    const char* charset = strlen(gen->charset) > 0 ? gen->charset :
                          "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    int charset_len = strlen(charset);
    
    char result[MAX_RECORD_SIZE] = {0};
    
    // Add prefix
    if (strlen(gen->prefix) > 0) {
        strncat(result, gen->prefix, sizeof(result) - strlen(result) - 1);
    }
    
    // Generate random string
    int prefix_len = strlen(result);
    for (int i = 0; i < length && (prefix_len + i) < (int)sizeof(result) - 1; i++) {
        result[prefix_len + i] = charset[random_int() % charset_len];
    }
    result[prefix_len + length] = '\0';
    
    // Add suffix
    if (strlen(gen->suffix) > 0) {
        strncat(result, gen->suffix, sizeof(result) - strlen(result) - 1);
    }
    
    strncpy(output, result, size);
}

void generate_name(char* output, size_t size, DataGenerator* gen) {
    const char* first = first_names[random_int() % (sizeof(first_names) / sizeof(first_names[0]))];
    const char* last = last_names[random_int() % (sizeof(last_names) / sizeof(last_names[0]))];
    snprintf(output, size, "%s %s", first, last);
}

void generate_email(char* output, size_t size, DataGenerator* gen) {
    char local[64];
    generate_string(local, sizeof(local), gen);
    // Remove any special chars for email local part
    for (int i = 0; local[i]; i++) {
        if (!isalnum(local[i])) local[i] = 'a' + (i % 26);
    }
    const char* domain = domains[random_int() % (sizeof(domains) / sizeof(domains[0]))];
    snprintf(output, size, "%s@%s", local, domain);
}

void generate_uuid(char* output, size_t size, DataGenerator* gen) {
    const char* hex = "0123456789abcdef";
    snprintf(output, size,
             "%c%c%c%c%c%c%c%c-%c%c%c%c-4%c%c%c-%c%c%c%c-%c%c%c%c%c%c%c%c%c%c%c%c",
             hex[random_int() % 16], hex[random_int() % 16], hex[random_int() % 16], hex[random_int() % 16],
             hex[random_int() % 16], hex[random_int() % 16], hex[random_int() % 16], hex[random_int() % 16],
             hex[random_int() % 16], hex[random_int() % 16], hex[random_int() % 16], hex[random_int() % 16],
             hex[random_int() % 16], hex[random_int() % 16], hex[random_int() % 16],
             hex[8 + random_int() % 4], hex[random_int() % 16], hex[random_int() % 16], hex[random_int() % 16],
             hex[random_int() % 16], hex[random_int() % 16], hex[random_int() % 16], hex[random_int() % 16],
             hex[random_int() % 16], hex[random_int() % 16], hex[random_int() % 16], hex[random_int() % 16],
             hex[random_int() % 16], hex[random_int() % 16], hex[random_int() % 16], hex[random_int() % 16]);
}

void generate_phone(char* output, size_t size, DataGenerator* gen) {
    int area = random_range(100, 999);
    int prefix = random_range(100, 999);
    int line = random_range(1000, 9999);
    snprintf(output, size, "(%03d) %03d-%04d", area, prefix, line);
}

void generate_address(char* output, size_t size, DataGenerator* gen) {
    int num = random_range(1, 9999);
    const char* street = streets[random_int() % (sizeof(streets) / sizeof(streets[0]))];
    const char* city = cities[random_int() % (sizeof(cities) / sizeof(cities[0]))];
    const char* state = states[random_int() % (sizeof(states) / sizeof(states[0]))];
    int zip = random_range(10000, 99999);
    snprintf(output, size, "%d %s, %s, %s %d", num, street, city, state, zip);
}

void generate_date(char* output, size_t size, DataGenerator* gen) {
    // Generate random date within last 10 years
    time_t now = time(NULL);
    time_t past = now - (10 * 365 * 24 * 60 * 60);
    time_t random_time = past + (time_t)(random_double() * (now - past));
    struct tm* tm_info = localtime(&random_time);
    strftime(output, size, "%Y-%m-%d", tm_info);
}

void generate_enum(char* output, size_t size, DataGenerator* gen) {
    if (gen->enum_count > 0) {
        int idx = random_int() % gen->enum_count;
        strncpy(output, gen->enum_values[idx], size);
    } else {
        strncpy(output, "unknown", size);
    }
}

void generate_value(char* output, size_t size, DataGenerator* gen) {
    switch (gen->type) {
        case GEN_INTEGER:
            generate_integer(output, size, gen);
            break;
        case GEN_FLOAT:
            generate_float(output, size, gen);
            break;
        case GEN_STRING:
            generate_string(output, size, gen);
            break;
        case GEN_NAME:
            generate_name(output, size, gen);
            break;
        case GEN_EMAIL:
            generate_email(output, size, gen);
            break;
        case GEN_UUID:
            generate_uuid(output, size, gen);
            break;
        case GEN_PHONE:
            generate_phone(output, size, gen);
            break;
        case GEN_ADDRESS:
            generate_address(output, size, gen);
            break;
        case GEN_DATE:
            generate_date(output, size, gen);
            break;
        case GEN_ENUM:
            generate_enum(output, size, gen);
            break;
        default:
            strncpy(output, "unknown", size);
            break;
    }
}

//=============================================================================
// Test Data Report Implementation
//=============================================================================

TestDataReport* data_create_report(void) {
    TestDataReport* report = (TestDataReport*)calloc(1, sizeof(TestDataReport));
    report->generator_capacity = MAX_GENERATORS;
    report->generators = (DataGenerator*)calloc(report->generator_capacity, sizeof(DataGenerator));
    report->dataset_capacity = MAX_DATASETS;
    report->datasets = (DataSet*)calloc(report->dataset_capacity, sizeof(DataSet));
    seed_random(0);
    return report;
}

void data_destroy_report(TestDataReport* report) {
    if (!report) return;
    
    for (int i = 0; i < report->dataset_count; i++) {
        DataSet* ds = &report->datasets[i];
        for (int j = 0; j < ds->row_count; j++) {
            for (int k = 0; k < ds->column_count; k++) {
                free(ds->data[j][k]);
            }
            free(ds->data[j]);
        }
        free(ds->data);
        free(ds->columns);
    }
    
    free(report->generators);
    free(report->datasets);
    free(report);
}

DataGenerator* add_generator(TestDataReport* report, const char* name, GeneratorType type) {
    if (report->generator_count >= report->generator_capacity) return NULL;
    
    DataGenerator* gen = &report->generators[report->generator_count++];
    strncpy(gen->name, name, sizeof(gen->name) - 1);
    gen->type = type;
    gen->distribution = DIST_UNIFORM;
    gen->min_value = 0;
    gen->max_value = 100;
    gen->min_length = 5;
    gen->max_length = 20;
    gen->nullable = 0;
    gen->null_probability = 0.0;
    gen->mean = 50;
    gen->stddev = 10;
    gen->lambda = 1.0;
    return gen;
}

DataSet* create_dataset(TestDataReport* report, const char* name, int columns, int rows) {
    if (report->dataset_count >= report->dataset_capacity) return NULL;
    
    DataSet* ds = &report->datasets[report->dataset_count++];
    strncpy(ds->name, name, sizeof(ds->name) - 1);
    ds->column_capacity = columns;
    ds->columns = (char**)calloc(columns, sizeof(char*));
    ds->column_count = columns;
    ds->row_capacity = rows;
    ds->data = (char***)calloc(rows, sizeof(char**));
    strncpy(ds->format, "csv", sizeof(ds->format));
    return ds;
}

void generate_dataset(TestDataReport* report, DataSet* ds, DataGenerator** gens) {
    clock_t start = clock();
    
    for (int i = 0; i < ds->row_capacity && i < ds->row_capacity; i++) {
        ds->data[i] = (char**)calloc(ds->column_count, sizeof(char*));
        
        for (int j = 0; j < ds->column_count; j++) {
            ds->data[i][j] = (char*)calloc(MAX_RECORD_SIZE, 1);
            if (gens[j]) {
                generate_value(ds->data[i][j], MAX_RECORD_SIZE, gens[j]);
            } else {
                strncpy(ds->data[i][j], "N/A", MAX_RECORD_SIZE);
            }
            report->total_bytes += strlen(ds->data[i][j]);
        }
        
        ds->row_count++;
        report->total_records++;
    }
    
    clock_t end = clock();
    report->generation_time_ms = ((double)(end - start)) / CLOCKS_PER_SEC * 1000;
}

void export_csv(DataSet* ds, const char* filename) {
    FILE* f = fopen(filename, "w");
    if (!f) return;
    
    // Header
    for (int j = 0; j < ds->column_count; j++) {
        fprintf(f, "%s%s", ds->columns[j] ? ds->columns[j] : "col",
                j < ds->column_count - 1 ? "," : "\n");
    }
    
    // Data
    for (int i = 0; i < ds->row_count; i++) {
        for (int j = 0; j < ds->column_count; j++) {
            fprintf(f, "%s%s", ds->data[i][j],
                    j < ds->column_count - 1 ? "," : "\n");
        }
    }
    
    fclose(f);
    printf("  CSV exported: %s\n", filename);
}

void export_json(DataSet* ds, const char* filename) {
    FILE* f = fopen(filename, "w");
    if (!f) return;
    
    fprintf(f, "[\n");
    for (int i = 0; i < ds->row_count; i++) {
        fprintf(f, "  {\n");
        for (int j = 0; j < ds->column_count; j++) {
            fprintf(f, "    \"%s\": \"%s\"%s\n",
                    ds->columns[j] ? ds->columns[j] : "col",
                    ds->data[i][j],
                    j < ds->column_count - 1 ? "," : "");
        }
        fprintf(f, "  }%s\n", i < ds->row_count - 1 ? "," : "");
    }
    fprintf(f, "]\n");
    
    fclose(f);
    printf("  JSON exported: %s\n", filename);
}

void export_sql(DataSet* ds, const char* filename, const char* table_name) {
    FILE* f = fopen(filename, "w");
    if (!f) return;
    
    fprintf(f, "CREATE TABLE %s (\n", table_name);
    for (int j = 0; j < ds->column_count; j++) {
        fprintf(f, "  %s VARCHAR(255)%s\n",
                ds->columns[j] ? ds->columns[j] : "col",
                j < ds->column_count - 1 ? "," : "");
    }
    fprintf(f, ");\n\n");
    
    for (int i = 0; i < ds->row_count; i++) {
        fprintf(f, "INSERT INTO %s VALUES (", table_name);
        for (int j = 0; j < ds->column_count; j++) {
            fprintf(f, "'%s'%s", ds->data[i][j],
                    j < ds->column_count - 1 ? ", " : "");
        }
        fprintf(f, ");\n");
    }
    
    fclose(f);
    printf("  SQL exported: %s\n", filename);
}

//=============================================================================
// Report Generation
//=============================================================================

void print_data_summary(TestDataReport* report) {
    printf("\n");
    printf("=============================================================================\n");
    printf("  Test Data Generation Summary\n");
    printf("=============================================================================\n");
    printf("  Generators:           %d\n", report->generator_count);
    printf("  Datasets:             %d\n", report->dataset_count);
    printf("  Total Records:        %d\n", report->total_records);
    printf("  Total Bytes:          %d\n", report->total_bytes);
    printf("  Generation Time:      %.2f ms\n", report->generation_time_ms);
    printf("  Throughput:           %.0f records/sec\n",
           report->total_records / (report->generation_time_ms / 1000.0));
    printf("=============================================================================\n");
}

void export_data_report_json(TestDataReport* report, const char* filename) {
    FILE* f = fopen(filename, "w");
    if (!f) return;
    
    fprintf(f, "{\n");
    fprintf(f, "  \"summary\": {\n");
    fprintf(f, "    \"generators\": %d,\n", report->generator_count);
    fprintf(f, "    \"datasets\": %d,\n", report->dataset_count);
    fprintf(f, "    \"total_records\": %d,\n", report->total_records);
    fprintf(f, "    \"total_bytes\": %d,\n", report->total_bytes);
    fprintf(f, "    \"generation_time_ms\": %.2f\n", report->generation_time_ms);
    fprintf(f, "  },\n");
    fprintf(f, "  \"generators\": [\n");
    
    for (int i = 0; i < report->generator_count; i++) {
        DataGenerator* gen = &report->generators[i];
        fprintf(f, "    {\n");
        fprintf(f, "      \"name\": \"%s\",\n", gen->name);
        fprintf(f, "      \"type\": %d,\n", gen->type);
        fprintf(f, "      \"distribution\": %d\n", gen->distribution);
        fprintf(f, "    }%s\n", (i < report->generator_count - 1) ? "," : "");
    }
    
    fprintf(f, "  ]\n");
    fprintf(f, "}\n");
    
    fclose(f);
    printf("  Report exported: %s\n", filename);
}

//=============================================================================
// Main Entry Point
//=============================================================================

int main(int argc, char* argv[]) {
    printf("RawrXD Test Data Generator\n");
    printf("==========================\n\n");
    
    TestDataReport* report = data_create_report();
    
    // Create generators
    DataGenerator* id_gen = add_generator(report, "id", GEN_INTEGER);
    id_gen->min_value = 1;
    id_gen->max_value = 100000;
    
    DataGenerator* name_gen = add_generator(report, "name", GEN_NAME);
    
    DataGenerator* email_gen = add_generator(report, "email", GEN_EMAIL);
    email_gen->min_length = 5;
    email_gen->max_length = 10;
    
    DataGenerator* phone_gen = add_generator(report, "phone", GEN_PHONE);
    
    DataGenerator* address_gen = add_generator(report, "address", GEN_ADDRESS);
    
    DataGenerator* date_gen = add_generator(report, "created_date", GEN_DATE);
    
    // Create dataset
    DataSet* users = create_dataset(report, "users", 6, 100);
    users->columns[0] = strdup("id");
    users->columns[1] = strdup("name");
    users->columns[2] = strdup("email");
    users->columns[3] = strdup("phone");
    users->columns[4] = strdup("address");
    users->columns[5] = strdup("created_date");
    
    DataGenerator* gens[] = {id_gen, name_gen, email_gen, phone_gen, address_gen, date_gen};
    generate_dataset(report, users, gens);
    
    // Export
    export_csv(users, "test_data.csv");
    export_json(users, "test_data.json");
    export_sql(users, "test_data.sql", "users");
    
    // Generate reports
    print_data_summary(report);
    export_data_report_json(report, "test_data_report.json");
    
    printf("\nTest data generation complete!\n");
    
    data_destroy_report(report);
    return 0;
}
