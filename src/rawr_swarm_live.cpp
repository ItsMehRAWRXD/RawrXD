#include "RawrSwarmEvents.hpp"
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <deque>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <string>
#include <thread>
#include <vector>
#include <atomic>
#include <csignal>
#include <cctype>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <conio.h>
#else
#include <sys/ioctl.h>
#include <unistd.h>
#include <sys/select.h>
#include <termios.h>
#endif

using rawr::live::Event;
namespace {
std::atomic<bool> running{true};
void onSignal(int){running=false;}
std::string clipped(const std::string& s, int width){
    if(width<1)return {};
    std::string out;out.reserve((size_t)width);
    int visible=0;
    // Prevent console injection and invalid UTF-8 fragments from tool output.
    for(size_t i=0;i<s.size()&&visible<width;){
        unsigned char c=(unsigned char)s[i];
        if(c=='\t'){out+=' ';++visible;++i;continue;}
        if(c=='\n'||c=='\r'){out+=' ';++visible;++i;continue;}
        if(c<0x20||c==0x7f){out+='?';++visible;++i;continue;}
        size_t len= c<0x80?1:(c>=0xc2&&c<0xe0?2:(c>=0xe0&&c<0xf0?3:(c>=0xf0&&c<0xf5?4:1)));
        if(i+len>s.size())break;
        if(len>1){bool valid=true;for(size_t j=1;j<len;j++)if(((unsigned char)s[i+j]&0xc0)!=0x80)valid=false;
            if(!valid){out+='?';++visible;++i;continue;}}
        out.append(s,i,len);++visible;i+=len;
    }
    return out;
}
std::vector<std::string> splitLines(const std::string& text,size_t max=100){
    std::vector<std::string> out;size_t start=0;
    while(start<text.size()&&out.size()<max){size_t p=text.find('\n',start);if(p==std::string::npos)p=text.size();
        out.push_back(text.substr(start,p-start));start=p+1;}
    if(out.empty())out.emplace_back();return out;
}
struct Worker {std::string name,phase="idle",kind="",title="",task="";uint64_t steps=0,errors=0;};
struct State {
    std::map<std::string,Worker> workers;
    std::vector<std::string> order;
    std::deque<Event> feed;
    int selected=0;
    bool onlySelected=false,follow=true,paused=false;
    size_t scrollBack=0,received=0,malformed=0,failures=0,successes=0;
    std::string filepath;
    void add(const Event& e){
        ++received;
        auto [it,inserted]=workers.emplace(e.worker,Worker{.name=e.worker});
        if(inserted)order.push_back(e.worker);
        auto& w=it->second;
        w.kind=e.kind;w.title=e.title;w.phase=e.phase;w.task=e.task;
        if(e.phase=="start")++w.steps;
        if(e.phase=="fail"){++failures;++w.errors;}
        if(e.phase=="ok")++successes;
        feed.push_back(e);if(feed.size()>600)feed.pop_front();
        if(follow)scrollBack=0;
    }
};
class FileTail {
public:
    explicit FileTail(std::string path):path_(std::move(path)){}
    template<class Callback>void poll(Callback&& cb){
        std::error_code ec;
        auto size=std::filesystem::file_size(path_,ec);
        if(ec)return;
        if(size<pos_){pos_=0;partial_.clear();}
        if(size==pos_)return;
        std::ifstream f(path_,std::ios::binary);
        if(!f)return;
        f.seekg((std::streamoff)pos_);
        char buf[16384];
        while(f && pos_<size){
            size_t n=(size_t)std::min<uintmax_t>(size-pos_,sizeof(buf));
            f.read(buf,(std::streamsize)n);size_t got=(size_t)f.gcount();if(got==0)break;
            pos_+=got;partial_.append(buf,got);
            size_t end=0;
            while((end=partial_.find('\n'))!=std::string::npos){
                std::string line=partial_.substr(0,end);
                if(!line.empty()&&line.back()=='\r')line.pop_back();
                Event e;
                if(rawr::live::parse(line,e))cb(&e);else cb(nullptr);
                partial_.erase(0,end+1);
            }
            if(partial_.size()>4*1024*1024){partial_.clear();cb(nullptr);}
        }
    }
private:
    std::string path_,partial_;uintmax_t pos_=0;
};
std::string kindTag(std::string k){
    if(k=="read")return "READ ";if(k=="edit")return "EDIT ";if(k=="diff")return "DIFF ";
    if(k=="shell")return "SHELL";if(k=="output")return "OUT  ";if(k=="reason")return "THINK";
    if(k=="plan")return "PLAN ";if(k=="build")return "BUILD";if(k=="test")return "TEST ";
    if(k=="agent")return "AGENT";if(k=="error")return "ERROR";if(k=="checkpoint")return "SAVE ";
    if(k.size()>5)k.resize(5);return k;
}
std::string colorFor(const Event& e){
    if(e.phase=="fail"||e.kind=="error")return "\x1b[31m";
    if(e.phase=="ok")return "\x1b[32m";
    if(e.kind=="edit"||e.kind=="diff")return "\x1b[33m";
    if(e.kind=="reason"||e.kind=="plan")return "\x1b[35m";
    if(e.kind=="shell"||e.kind=="build")return "\x1b[36m";
    return "\x1b[37m";
}
std::string eventLabel(const Event& e,int width,bool vt){
    std::string worker=e.worker;if(worker.size()>13)worker=worker.substr(0,13);
    std::string prefix="["+kindTag(e.kind)+"] "+worker+" "+e.phase+"  ";
    std::string title=clipped(e.title,std::max(1,width-(int)prefix.size()));
    return (vt?colorFor(e):std::string())+clipped(prefix+title,width)+(vt?"\x1b[0m":"");
}
std::string shortenPath(std::string path,int n){
    if((int)path.size()<=n)return path;
    if(n<8)return path.substr(0,(size_t)std::max(0,n));
    return path.substr(0,3)+"..."+path.substr(path.size()-(size_t)(n-6));
}
class Screen {
public:
    bool start(){
#ifdef _WIN32
        out_=GetStdHandle(STD_OUTPUT_HANDLE);in_=GetStdHandle(STD_INPUT_HANDLE);
        DWORD orig=0;DWORD inMode=0;
        if(out_==INVALID_HANDLE_VALUE||!GetConsoleMode(out_,&orig)||!GetConsoleMode(in_,&inMode))return false;
        origOut_=orig;origIn_=inMode;
        if(!SetConsoleMode(out_,orig|ENABLE_VIRTUAL_TERMINAL_PROCESSING))return false;
        if(!SetConsoleOutputCP(CP_UTF8))return false;
#else
        if(!isatty(fileno(stdout))||!isatty(fileno(stdin)))return false;
        if(tcgetattr(STDIN_FILENO,&saved_)!=0)return false;
        struct termios term=saved_;
        term.c_lflag &= (tcflag_t)~(ICANON|ECHO);
        term.c_cc[VMIN]=0;term.c_cc[VTIME]=0;
        if(tcsetattr(STDIN_FILENO,TCSANOW,&term)!=0)return false;
#endif
        active_=true;std::fputs("\x1b[?1049h\x1b[?25l\x1b[H",stdout);std::fflush(stdout);return true;
    }
    void stop(){if(!active_)return;std::fputs("\x1b[0m\x1b[?25h\x1b[?1049l",stdout);std::fflush(stdout);
#ifdef _WIN32
        SetConsoleMode(out_,origOut_);SetConsoleMode(in_,origIn_);
#else
        tcsetattr(STDIN_FILENO,TCSANOW,&saved_);
#endif
        active_=false;
    }
    ~Screen(){stop();}
    int key(){
#ifdef _WIN32
        return _kbhit()?_getch():-1;
#else
        fd_set fds;FD_ZERO(&fds);FD_SET(STDIN_FILENO,&fds);struct timeval t{};
        if(select(STDIN_FILENO+1,&fds,nullptr,nullptr,&t)>0){unsigned char c;if(read(STDIN_FILENO,&c,1)==1)return c;}
        return -1;
#endif
    }
    std::pair<int,int> size()const{
#ifdef _WIN32
        CONSOLE_SCREEN_BUFFER_INFO cs{};if(GetConsoleScreenBufferInfo(out_,&cs))return {cs.srWindow.Right-cs.srWindow.Left+1,cs.srWindow.Bottom-cs.srWindow.Top+1};
#else
        struct winsize w{};if(ioctl(STDOUT_FILENO,TIOCGWINSZ,&w)==0)return {(int)w.ws_col,(int)w.ws_row};
#endif
        return {100,32};
    }
    void show(std::string&& frame){if(active_){std::fputs("\x1b[H",stdout);std::fwrite(frame.data(),1,frame.size(),stdout);std::fputs("\x1b[J",stdout);std::fflush(stdout);}}
private:
    bool active_=false;
#ifdef _WIN32
    HANDLE out_=INVALID_HANDLE_VALUE,in_=INVALID_HANDLE_VALUE;DWORD origOut_=0,origIn_=0;
#else
    struct termios saved_{};
#endif
};
void render(Screen& screen,const State& s){
    auto [cols,rows]=screen.size();cols=std::clamp(cols,48,220);rows=std::clamp(rows,12,80);
    const int left=std::min(29,std::max(17,cols/3));const int right=cols-left-3;
    std::string out;out.reserve((size_t)cols*(size_t)rows*2);
    auto row=[&](std::string a){out+=clipped(a,cols);out+='\n';};
    row("RawrXD SWARM / LIVE WORKBENCH   events="+std::to_string(s.received)+
        " ok="+std::to_string(s.successes)+" fail="+std::to_string(s.failures)+" invalid="+std::to_string(s.malformed));
    row("watch: "+shortenPath(s.filepath,cols-10));
    row(std::string((size_t)cols,'='));
    row("WORKERS"+std::string((size_t)std::max(1,left-7),' ')+" | ACTIVITY  [READ / EDIT / SHELL / PLAN / REASON / TEST]");
    const int detail=std::min(7,std::max(3,rows/5));
    const int body=std::max(2,rows-9-detail);
    std::vector<Event> display;
    for(const auto& e:s.feed){if(!s.onlySelected || (s.selected<(int)s.order.size()&&e.worker==s.order[(size_t)s.selected]))display.push_back(e);}
    size_t n=display.size();size_t back=std::min(s.scrollBack,n);size_t end=n-back;
    size_t begin=end>(size_t)body?end-(size_t)body:0;
    for(int i=0;i<body;++i){
        std::string a="";
        if((size_t)i<s.order.size()){
            const auto& id=s.order[(size_t)i];const auto& w=s.workers.at(id);
            a=(i==s.selected?"> ":"  ")+shortenPath(w.name,left-6)+" "+w.phase;
        }
        std::string b="";size_t idx=begin+(size_t)i;
        if(idx<end)b=eventLabel(display[idx],right,true);
        out+=clipped(a,left);if((int)clipped(a,left).size()<left)out+=std::string((size_t)(left-(int)clipped(a,left).size()),' ');
        out+=" | ";out+=b;out+='\n';
    }
    row(std::string((size_t)cols,'-'));
    row("SELECTED WORKER DETAILS  [Tab/1-9 select, f filter, j/k scroll, g follow, p pause, q detach]");
    std::string who=s.selected<(int)s.order.size()?s.order[(size_t)s.selected]:"(none)";
    row("Worker: "+who);
    std::vector<const Event*> recent;
    for(auto it=s.feed.rbegin();it!=s.feed.rend()&&recent.size()<(size_t)detail; ++it)
        if(it->worker==who)recent.push_back(&*it);
    if(!recent.empty()) {
        auto last=recent.front();
        row("Latest: "+last->kind+" / "+last->phase+" - "+last->title+
            (last->exitCode==-1?"":"  exit="+std::to_string(last->exitCode)));
        size_t emitted=0;
        for(auto *e: recent) {
            if(emitted>=(size_t)detail)break;
            std::string prefix=(e->kind=="reason"?"~ ":e->kind=="read"?"> ":e->kind=="edit"?"+ ":e->kind=="shell"?"$ ":e->kind=="output"?"| ":"= ");
            if(e->detail.empty()) {row("  "+prefix+e->title);++emitted;continue;}
            for(const auto& l:splitLines(e->detail,3)) {
                if(emitted>=(size_t)detail)break;
                row("  "+prefix+l);++emitted;
            }
        }
        while(emitted++<(size_t)detail)row("");
    } else {row("No events yet");for(int i=0;i<detail;++i)row("");}
    row("[q] detach only (does not stop agents)  [p] freeze view  [f] selected/all  [j/k] scroll  [g] follow");
    screen.show(std::move(out));
}
int dump(const std::string& path){
    FileTail tail(path);bool any=false;size_t invalid=0;
    tail.poll([&](const Event* e){if(!e){++invalid;return;}any=true;
        std::cout<<e->ts<<" ["<<kindTag(e->kind)<<"] ["<<e->worker<<"] "<<e->phase<<": "<<clipped(e->title,140)<<"\n";
        if(!e->detail.empty())for(const auto& l:splitLines(e->detail,10))std::cout<<"    "<<clipped(l,180)<<"\n";
        if(e->exitCode!=-1)std::cout<<"    exit="<<e->exitCode<<"\n";
    });
    if(invalid)std::cerr<<invalid<<" malformed/overlength records\n";
    if(!any){std::cerr<<"No parseable events in "<<path<<"\n";return 2;}
    return invalid?3:0;
}
void help(){std::cout<<"RawrXD live swarm viewer (native C++20)\n"
       "  rawr_swarm_live watch <events.jsonl> [--plain]\n"
       "  rawr_swarm_live open  <events.jsonl>    (Windows new console)\n"
       "  rawr_swarm_live dump  <events.jsonl>    (bounded replay)\n"
       "Keys: Tab / 1-9 select; f filter; j/k scroll; g follow; p pause; q detach.\n"
       "This viewer only renders events emitted by actual RawrXD tool/agent execution.\n";}
}
int main(int argc,char**argv){
    if(argc<3){help();return 2;}
    const std::string verb=argv[1],path=argv[2];
    if(verb=="dump")return dump(path);
    if(verb=="open"){
        std::string error;if(rawr::live::openViewerWindow(argv[0],path,&error))return 0;
        std::cerr<<"Unable to open viewer: "<<error<<"\n";return 1;
    }
    if(verb!="watch"){help();return 2;}
    std::signal(SIGINT,onSignal);
    bool plain=argc>3 && std::string(argv[3])=="--plain";
    Screen screen;bool tui=!plain && screen.start();
    State state;state.filepath=path;
    FileTail tail(path);
    auto handle=[&](const Event* e){if(!e){++state.malformed;return;}state.add(*e);
        if(!tui)std::cout<<e->ts<<" ["<<e->kind<<"/"<<e->phase<<"] "<<e->worker<<": "<<clipped(e->title,150)<<" "<<clipped(e->detail,300)<<std::endl;
    };
    while(running){
        if(!state.paused)tail.poll(handle);
        if(tui){
            for(int k=screen.key();k!=-1;k=screen.key()){
                if(k=='q'||k=='Q'){running=false;break;}
                if(k=='p')state.paused=!state.paused;
                if(k=='f')state.onlySelected=!state.onlySelected;
                if(k=='g'){state.follow=true;state.scrollBack=0;}
                if(k=='j'){state.follow=false;state.scrollBack+=1;}
                if(k=='k'){state.scrollBack=state.scrollBack>0?state.scrollBack-1:0;}
                if(k=='\t' && !state.order.empty())state.selected=(state.selected+1)%(int)state.order.size();
                if(k>='1'&&k<='9'&&(size_t)(k-'1')<state.order.size())state.selected=k-'1';
            }
            render(screen,state);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(120)); // UI refresh only, never controls model/streamer
    }
    screen.stop();return 0;
}
