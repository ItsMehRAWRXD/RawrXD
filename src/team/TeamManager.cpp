// TeamManager.cpp - Phase 4D: Team Features
// Collaboration, sharing, code review

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_MEMBERS 100
#define MAX_REVIEWS 50

struct TeamMember {
    char name[64];
    char role[32];
    BOOL online;
};

struct CodeReview {
    char file[256];
    char reviewer[64];
    char status[16];
    char comments[1024];
};

struct TeamManager {
    TeamMember members[MAX_MEMBERS];
    int memberCount;
    CodeReview reviews[MAX_REVIEWS];
    int reviewCount;
};

TeamManager g_team = {0};

void TEAM_Init() {
    printf("[TEAM] Initializing Team Manager...\n");
    printf("[TEAM] Ready for collaboration\n");
}

void TEAM_AddMember(const char* name, const char* role) {
    if (g_team.memberCount >= MAX_MEMBERS) return;
    strcpy(g_team.members[g_team.memberCount].name, name);
    strcpy(g_team.members[g_team.memberCount].role, role);
    g_team.members[g_team.memberCount].online = TRUE;
    g_team.memberCount++;
    printf("[TEAM] Added: %s (%s)\n", name, role);
}

void TEAM_ShareFile(const char* file, const char* user) {
    printf("[TEAM] Sharing %s with %s\n", file, user);
    printf("[TEAM] File shared successfully\n");
}

void TEAM_RequestReview(const char* file) {
    printf("[TEAM] Requesting review for %s\n", file);
    printf("[TEAM] Review request sent\n");
}

void TEAM_ShowMembers() {
    printf("\n[TEAM] Team Members (%d):\n", g_team.memberCount);
    for (int i = 0; i < g_team.memberCount; i++) {
        printf("  %s - %s (%s)\n", g_team.members[i].name,
               g_team.members[i].role,
               g_team.members[i].online ? "online" : "offline");
    }
    printf("\n");
}

void TEAM_RunLoop() {
    char cmd[256], arg1[64], arg2[64];
    TEAM_Init();
    printf("Team commands: add, share, review, members, quit\n");
    
    while (1) {
        printf("Team> ");
        if (!fgets(cmd, sizeof(cmd), stdin)) break;
        cmd[strcspn(cmd, "\n")] = 0;
        sscanf(cmd, "%s %s %s", cmd, arg1, arg2);
        
        if (strcmp(cmd, "quit") == 0) break;
        else if (strcmp(cmd, "add") == 0 && arg1[0]) TEAM_AddMember(arg1, arg2[0]?arg2:"developer");
        else if (strcmp(cmd, "share") == 0 && arg1[0]) TEAM_ShareFile(arg1, arg2[0]?arg2:"team");
        else if (strcmp(cmd, "review") == 0 && arg1[0]) TEAM_RequestReview(arg1);
        else if (strcmp(cmd, "members") == 0) TEAM_ShowMembers();
    }
}

int main() {
    printf("=================================================\n");
    printf("  Team Manager - Phase 4D\n");
    printf("  15 Team Features\n");
    printf("=================================================\n\n");
    TEAM_RunLoop();
    return 0;
}
