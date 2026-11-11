#pragma once

class Win32IDE;

void Win32IDE_gitStage(const std::string& file);
void Win32IDE_gitCommit(const std::string& message);
void Win32IDE_gitPush();
void Win32IDE_gitPull();
void Win32IDE_gitBranch(const std::string& name);
void Win32IDE_gitStash();
void Win32IDE_gitCherryPick(const std::string& commit);
void Win32IDE_gitStatus();
