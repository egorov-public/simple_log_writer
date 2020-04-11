#ifndef DEBUGLOG_H
#define DEBUGLOG_H

/*
Usage: (THIS IS A VERY LIGHT IMPLEMENTATION, NO DEPENDS, MAX SPEED, LOW SIZE, POWERFUL)

1. Somewhere in module define macros 'DEFINE_LOG', that is define logentry there log is created
Example:
DEFINE_LOG
void main()
{
__Debug(__T("main: Start of the programm %s"), __T("some TCHAR string"));
...

or
DEFINE_LOG
int DllMain(...)
{
...
__Error(__T("DllMain: SomeFailed %ls(%S) - %e"), L"Long string", TwoByteString, ::GetLastError());
...

2. In every file where you are goint to use log include this file.
3. In project options declare 'USELOGS' if you wish use logs, and not declare if you don't.
4. If you want use log in single threaded application or already sunchronous code - define 'SINGLETHREAD_LOGS'

This logs are implemented base on templates, many functions is inline and very simple,
so logs are very fast. You can extend logs by writing you own class with public 'Write'
function and extend logs as you wish.

Logs is for Windows/Unix platforms.

    Supported formats:
    %c  - char
    %d  - int
    %hd - short
    %u  - unsigned int
    %hu - unsigned short
    %x  - hex
    %e  - formate windows error code
    %s  - string
    %ls - width string
    %I64d- int64
    %I64u- unsigned int64
    %S - always 2 bytes per element string
    %b - true or false

*/

#include <time.h>
#include <vector>
#include <cassert>
#include <string.h>
#include <string>

#ifndef _WIN32
#include <stdarg.h>
#include <wchar.h>
#include <pthread.h>
#include <stdint.h>
#include <valarray>
#include <errno.h>
# ifdef _UNICODE
# define __T(s) L##s
# define TCHAR wchar_t
# else
# define __T(s) s
# define TCHAR char
# endif
#else
#include <windows.h>
#include <tchar.h>
#include <Tlhelp32.h>
#include <list>
#include <algorithm>
#pragma warning(disable:4786)
#endif

namespace Debug
{
#if defined (_WIN32)
  class LogsSyncModel
  {
  public:
    LogsSyncModel(){::InitializeCriticalSection(&_cs);}
    ~LogsSyncModel(){::DeleteCriticalSection(&_cs);}
    inline void Lock(){::EnterCriticalSection(&_cs);}
    inline void Unlock(){::LeaveCriticalSection(&_cs);}
  private:
    CRITICAL_SECTION _cs;
  };
#else
  class LogsSyncModel
  {
  public:
    LogsSyncModel(){pthread_mutex_init(&_cs, NULL);}
    ~LogsSyncModel(){pthread_mutex_destroy(&_cs);}
    inline void Lock(){pthread_mutex_lock(&_cs);}
    inline void Unlock(){pthread_mutex_unlock(&_cs);}
  private:
    pthread_mutex_t _cs;
  };
#endif

  template<class CharType>
  class Log
  {
  public:
    virtual ~Log() {}  
    //! Write line to log.
    virtual void Trace(const CharType* format, ...) = 0;
    //! Write to line of the log.
    virtual void WriteLog(const CharType* format, ...) = 0;
  };

  ////////////////////////////////////////////////////////////////////////////////////////////
  // Stringhelpers

  template<class CharType>
  const CharType* string_char(const CharType* s, CharType c);

  template<>
  inline const char* string_char<char>(const char* s, char c)
  {
    return strchr(s, c);
  }
  template<>
  inline const wchar_t* string_char<wchar_t>(const wchar_t* s, wchar_t c)
  {
    return wcschr(s, c);
  }

  template<class CharType>
  size_t string_len(const CharType* s)
  {
    size_t l = 0;
    while (s[l])
      ++l;
    return l;
  }

  template<>
  inline size_t string_len<char>(const char* s)
  {
    return strlen(s);
  }
  template<>
  inline size_t string_len<wchar_t>(const wchar_t* s)
  {
    return wcslen(s);
  }

  template<class CharType, class CharTypeRes>
  std::basic_string<CharTypeRes>& string_convert(const CharType* s, std::basic_string<CharTypeRes>& result);

  template<class CharType>
  inline std::basic_string<CharType>& string_convert(const CharType* s, std::basic_string<CharType>& result)
  {
    result = s;
    return result;
  }
  template<class CharType>
  inline std::basic_string<CharType>& string_convert(const short* s, std::basic_string<CharType>& result)
  {
    std::copy(s, s + string_len(s), std::back_inserter(result));
    return result;
  }

#ifdef _WIN32
  template<>
  std::basic_string<wchar_t>& string_convert<char, wchar_t>(const char* s, std::basic_string<wchar_t>& result)
  {
    result.clear();
    int requiredSize = ::MultiByteToWideChar(CP_ACP, 0, s, -1, NULL, 0);
    assert(requiredSize);
    if (!requiredSize)
      return result;
    std::vector<wchar_t> buff(requiredSize+1, 0);
    requiredSize = ::MultiByteToWideChar(CP_ACP, 0, s, -1, &buff[0], (int)buff.size());
    assert(requiredSize);
    result = &buff[0];
    return result;
  }
#else
  template<>
  std::wstring& string_convert<char, wchar_t>(const char* s, std::wstring& result)
  {
    std::vector<wchar_t> buff(string_len(s) + 1, 0);
    size_t requiredSize = ::mbstowcs(&buff[0], s, buff.size());
    if (requiredSize > buff.size())
    {
      buff.resize(requiredSize + 1);
      requiredSize = ::mbstowcs(&buff[0], s, buff.size());
      if (requiredSize == 0 || requiredSize == (size_t)-1)
        buff.clear();
    }				
    result = &buff[0];
    return result;
  }

  template<>
  std::string& string_convert<wchar_t, char>(const wchar_t* s, std::string& result)
  {
    std::vector<char> buff(string_len(s)+1, 0);
    size_t requiredSize = ::wcstombs(&buff[0], s, buff.size());
    if (requiredSize > buff.size())
    {
      buff.resize(requiredSize + 1);
      requiredSize = ::wcstombs(&buff[0], s, buff.size());
      if (requiredSize == 0 || requiredSize == (size_t)-1)
        buff.clear();
    }				
    result = &buff[0];
    return result;
  }
#endif//_WIN32

  template<class CharType>
  bool string_isspace(CharType c);

  template<>
  inline bool string_isspace<char>(char c)
  {
    return isspace(c);
  }
  template<>
  inline bool string_isspace<wchar_t>(wchar_t c)
  {
    return iswspace(c);
  }

  template<class CharType>
  void string_trim_right(CharType* s, size_t len)
  {
    while (len && string_isspace(s[len-1]))
    {
      s[--len] = 0;
    }
  }

  template<class CharType>
  int string_cmp(const CharType* ls, const CharType* rs, size_t len);

  template<>
  inline int string_cmp<char>(const char* ls, const char* rs, size_t len)
  {
    return strncmp(ls, rs, len);
  }
  template<>
  inline int string_cmp<wchar_t>(const wchar_t* ls, const wchar_t* rs, size_t len)
  {
    return wcsncmp(ls, rs, len);
  }

  template<class CharType>
  inline std::basic_string<CharType> GetEOL()
  {
#ifdef _WIN32  
    const CharType EOL[] = {'\r','\n',0};
#else
    const CharType EOL[] = {'\n',0};
#endif
    return std::basic_string<CharType>(EOL,string_len(EOL));
  }

  //////////////////////////////////////////////////////////////////////////////
  // Helpers fot conversion integrals to string`

  template<class CharType, class IntType>
  CharType* to_hex(IntType val, CharType* buff, size_t size);

  template<>
  inline char* to_hex<char,int>(int val, char* buff, size_t size)
  {
    snprintf(buff, size, "%x", val);
    return buff;
  }
  template<>
  inline wchar_t* to_hex<wchar_t,int>(int val, wchar_t* buff, size_t size)
  {
    swprintf(buff, size, L"%x", val);
    return buff;
  }

  template<class CharType, class IntType>
  CharType* to_dec(IntType val, CharType* buff, size_t size);

  template<>
  inline char* to_dec<char,short>(short val, char* buff, size_t size)
  {
    snprintf(buff, size, "%hd", val);
    return buff;
  }
  template<>
  inline wchar_t* to_dec<wchar_t,short>(short val, wchar_t* buff, size_t size)
  {
    swprintf(buff, size, L"%hd", val);
    return buff;
  }

  template<>
  inline char* to_dec<char,unsigned short>(unsigned short val, char* buff, size_t size)
  {
    snprintf(buff, size, "%hu", val);
    return buff;
  }
  template<>
  inline wchar_t* to_dec<wchar_t,unsigned short>(unsigned short val, wchar_t* buff, size_t size)
  {
    swprintf(buff, size, L"%hu", val);
    return buff;
  }

  template<>
  inline char* to_dec<char,int>(int val, char* buff, size_t size)
  {
    snprintf(buff, size, "%d", val);
    return buff;
  }
  template<>
  inline wchar_t* to_dec<wchar_t,int>(int val, wchar_t* buff, size_t size)
  {
    swprintf(buff, size, L"%d", val);
    return buff;
  } 

  template<>
  inline char* to_dec<char,unsigned>(unsigned val, char* buff, size_t size)
  {
    snprintf(buff, size, "%u", val);
    return buff;
  }
  template<>
  inline wchar_t* to_dec<wchar_t,unsigned>(unsigned val, wchar_t* buff, size_t size)
  {
    swprintf(buff, size, L"%u", val);
    return buff;
  }

  template<>
  inline char* to_dec<char,int64_t>(int64_t val, char* buff, size_t size)
  {
#ifdef _WIN32
    snprintf(buff, size, "%I64d", val);
#else
    snprintf(buff, size, "%lld", val);
#endif
    return buff;
  }
  template<>
  inline wchar_t* to_dec<wchar_t,int64_t>(int64_t val, wchar_t* buff, size_t size)
  {
#ifdef _WIN32
    swprintf(buff, size, L"%I64d", val);
#else
    swprintf(buff, size, L"%lld", val);
#endif
    return buff;
  }

  template<>
  inline char* to_dec<char,uint64_t>(uint64_t val, char* buff, size_t size)
  {
#ifdef _WIN32
    snprintf(buff, size, "%I64u", val);
#else
    snprintf(buff, size, "%llu", val);
#endif
    return buff;
  }
  template<>
  inline wchar_t* to_dec<wchar_t,uint64_t>(uint64_t val, wchar_t* buff, size_t size)
  {
#ifdef _WIN32
    swprintf(buff, size, L"%I64u", val);
#else
    swprintf(buff, size, L"%llu", val);
#endif
    return buff;
  }
  
  
  //////////////////////////////////////////////////////////////////////////////

  template<class CharType>
  class LogImpl : public LogsSyncModel, public Log<CharType>
  {
  public:

    virtual void Trace(const CharType* format, ...)
    {
      va_list args;
      va_start(args, format);
      Format(format, args);
      va_end(args);
      Write(GetEOL<CharType>());
      LogsSyncModel::Unlock();//Log befor one log entry
    }

    virtual void WriteLog(const CharType* format, ...)
    {
      va_list args;
      va_start(args, format);
      Format(format, args);
      va_end(args);
    }
  protected:
    virtual void Write(const CharType* s, size_t len) = 0;

  private: 
    void Format(const CharType* format, va_list args)
    {
      const CharType True[] = {'t','r','u','e',0};
      const CharType False[] = {'f','a','l','s','e',0};
      const CharType S64[] = {'I','6','4','d',0};
      const CharType U64[] = {'I','6','4','u',0};
      
      const size_t BUFFSIZE = 72;
      CharType Buff[BUFFSIZE];

      const CharType* p = format;
      const CharType* specifier = string_char(p, CharType('%'));

      while (specifier && *specifier)
      {
        Write(p, specifier - p);
        ++specifier;//skip '%'

        switch ((char)*specifier)
        {
        case 'c':
          {
            const CharType c = static_cast<CharType>(va_arg(args, int));
            Write(&c, 1);
            break;
          }
        case 'b':
          {
            const bool b = static_cast<bool>(va_arg(args, int));
            WriteString(b ? True : False);
            break;
          }
        case 'h':
          {
            switch (*(++specifier))
            {
            case 's':
              WriteString(va_arg(args, char*));
              break;
            case 'd':
              WriteString(to_dec(static_cast<short>(va_arg(args, int)), Buff, BUFFSIZE));
              break;
            case 'u':
              WriteString(to_dec(static_cast<unsigned short>(va_arg(args, int)), Buff, BUFFSIZE));
              break;
            default:
              assert(!"Unknown specifier!");
            };
            break;
          }
        case 'u':
          WriteString(to_dec(va_arg(args, unsigned), Buff, BUFFSIZE));
          break;
        case 'x':
          WriteString(to_hex(va_arg(args, int), Buff, BUFFSIZE));
          break;
        case 'd':
          WriteString(to_dec(va_arg(args, int), Buff, BUFFSIZE)); 
          break;
        case 'e':
          {
            const unsigned e = va_arg(args, unsigned);
#ifdef _WIN32
            LPTSTR Message = 0;
            if (const DWORD message_len = ::FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER|FORMAT_MESSAGE_FROM_SYSTEM|FORMAT_MESSAGE_IGNORE_INSERTS, 
              NULL, e, LANG_USER_DEFAULT, (LPTSTR)&Message, 0, NULL) != 0)
            {
              const CharType QUOTE[] = {'\'', 0};
              const CharType DEFICE[] = {' ', '-', ' ', 0};
              
              Write(QUOTE, 1);
              string_trim_right(Message, message_len);
              std::basic_string<CharType> res;              
              string_convert(Message, res);
              res += QUOTE;
              res += DEFICE;
              Write(res);

              LocalFree(Message);
            }
#endif					
            const CharType fmt[] = {'[','0','x','%','x',']',0};
            WriteLog(fmt, e);
            break;
          }
        case 's':
          {
            WriteString(va_arg(args, CharType*));
            break;
          }
        case 'S':
          {
            typedef short AChar;
            WriteString(va_arg(args, AChar*));
            break;
          }
        case 'l':
          {
            if (*(++specifier) != 's')
            {
              assert(!"Unknown specifier!");
              break;//skip unknown
            }
            WriteString(va_arg(args, wchar_t*));
            break;
          }
        case 'I':
          {
            const bool bSigned = string_cmp(specifier, S64, 4) == 0;
            if (!bSigned && string_cmp(specifier, U64, 4) != 0)
            {
              assert(!"Unknown specifier!");
              break;//skip unknown
            }
            specifier += 3;//skip 'I64', 'd' will be skipped later
            WriteString(bSigned ? to_dec(static_cast<int64_t>(va_arg(args, int64_t)), Buff, 65) : 
             to_dec(static_cast<uint64_t>(va_arg(args, uint64_t)), Buff, 65));
          }
          break; 
        case '%':
          {
            const CharType PERCENT[] = {'%', 0};
            WriteString(PERCENT);
          }
          break;
        default:
          //skip UNKNOWN
          break;
        };

        ++specifier;//skip cpesifier itself
        p = string_char(specifier, CharType('%'));
        std::swap(p, specifier);
      }

      if (p && *p) 
        Write(p, string_len(p));
    }

    inline void Write(const std::basic_string<CharType>& s)
    {
      Write(s.c_str(), s.size());
    }

    template<class StringChar>
    inline void WriteString(const StringChar* s)
    {
      const CharType null[] = {'n','u','l','l',0};    
      if (!s)
        Write(null, string_len(null));    
      else
      {
        std::basic_string<CharType> res;
        Write(string_convert(s, res));
      }
    }

    inline void WriteString(const CharType* s)
    {
      const CharType null[] = {'n','u','l','l',0};    
      if (!s)
        Write(null, string_len(null));    
      else
        Write(s, string_len(s));
    }
  };

  //////////////////////////////////////////////////////////////////////////////////////////////////////////////
  // Write to file

  template<class CharType>
  class FileWriter
  {
  public:
    FileWriter()
    {
#ifdef _WIN32
      const CharType UNDERSCORE[] = {'_', 0};
      std::basic_string<CharType> longname(GetModuleName() + UNDERSCORE);

      
      std::basic_string<CharType> compName;
      if (GetComputerName(compName))
        logname += compName + '_';

      time_t t = time(NULL);
      CharType Buff[MAX_PATH] = {0};

      tm tms = {0};
      localtime_s(&tms, &t);
      _stprintf_s(Buff, MAX_PATH, __T("%d-%d-%d_%d-%d-%d.txt"), 
        tms.tm_mday, tms.tm_mon, 1900 + tms.tm_year, tms.tm_hour, tms.tm_min, tms.tm_sec);

      logname += Buff;
      _tfopen_s(&_file, logname.c_str(), __T("w+bcS"));

#else
      std::string logname(program_invocation_name);
      if (!logname.empty())
        logname += "_";
      time_t t = time(NULL);
      const tm* tms = localtime(&t);

      char Buff[128];
      snprintf(Buff, 127, "%d-%d-%d_%d-%d-%d.txt", 
        tms->tm_mday, tms->tm_mon, tms->tm_year, tms->tm_hour, tms->tm_min, tms->tm_sec);

      logname += Buff;

      _file = fopen(logname.c_str(), "w+bc");
#endif

      if (_file)
      {
        setvbuf (_file, NULL, _IONBF, 0);
        std::basic_string<CharType> res;
        string_convert("====================== LOG OPEN ======================", res);
        res += GetEOL<CharType>();
        fwrite(res.c_str(), sizeof(CharType), res.size(), _file);
      }
    }
    ~FileWriter()
    {
      if (_file)
      {
        std::basic_string<CharType> res;
        string_convert("====================== LOG CLOSE =====================", res);
        res += GetEOL<CharType>();
        fwrite(res.c_str(), sizeof(CharType), res.size(), _file);
        fclose(_file);
      }
    }

  private:
#ifdef _WIN32
    bool GetCompuerName(const std::string& name)const
    {
      DWORD size = MAX_PATH;
      char buff[MAX_PATH] = {0};
      const BOOL res = ::GetComputerNameA(buff, &size);
      if (res)
        name = buff;
      return res;
    }
    bool GetCompuerName(const std::wstring& name)const
    {
      DWORD size = MAX_PATH;
      wchar_t buff[MAX_PATH] = {0};
      const BOOL res = ::GetComputerNameW(buff, &size);
      if (res)
        name = buff;
      return res;
    }
    std::basic_string<TCHAR> GetModuleName()const
    {
      std::vector<HMODULE> modulesArray;
      HMODULE hModule = ::LoadLibrary(__T("psapi"));
      if (hModule)
      {
        //psapi for windows NT, 2000, XP
        typedef BOOL (WINAPI *EnumProcessModulesFunc)(HANDLE,HMODULE*,DWORD,LPDWORD);
        EnumProcessModulesFunc EnumPM = (EnumProcessModulesFunc)GetProcAddress(hModule, "EnumProcessModules");

        DWORD neededbytes = 0;
        std::vector<HMODULE> Buffer(1024);
        if (EnumPM(GetCurrentProcess(), &Buffer[0], (DWORD)Buffer.size()*sizeof(HMODULE), &neededbytes))
        {
          neededbytes /= sizeof(HMODULE); 
          if (Buffer.size() < neededbytes)
          {
            Buffer.resize(neededbytes);
            if (!EnumPM(GetCurrentProcess(), &Buffer[0], (DWORD)Buffer.size()*sizeof(HMODULE), &neededbytes))
              neededbytes = 0;
          }
          else
          {
            Buffer.resize(neededbytes);
          }
          modulesArray.swap(Buffer);
        }
        FreeLibrary(hModule);
      }

      if (modulesArray.empty())
      {
        //for 9x 2000 XP
        typedef HANDLE (WINAPI *CreateToolhelp32SnapshotFunc)(DWORD,DWORD);
        typedef BOOL (WINAPI *Module32FirstFunc)(HANDLE,LPMODULEENTRY32);
        typedef BOOL (WINAPI *Module32NextFunc)(HANDLE,LPMODULEENTRY32);

        hModule = ::LoadLibrary(__T("Kernel32"));
        if (hModule)
        {
          CreateToolhelp32SnapshotFunc CreateSnapshot = 
            (CreateToolhelp32SnapshotFunc)GetProcAddress(hModule, "CreateToolhelp32Snapshot");

          if (CreateSnapshot)
          {
            HANDLE ttapi = CreateSnapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
            if (ttapi != INVALID_HANDLE_VALUE)
            {
              Module32FirstFunc ModuleFirst = 
                (Module32FirstFunc)GetProcAddress(hModule, "Module32First");

              Module32NextFunc ModuleNext = 
                (Module32NextFunc)GetProcAddress(hModule, "Module32Next");

              MODULEENTRY32 module_entry;
              module_entry.dwSize = sizeof(MODULEENTRY32);
              if (ModuleFirst(ttapi, &module_entry))
              {
                modulesArray.push_back(module_entry.hModule);
                module_entry.dwSize = sizeof(MODULEENTRY32);

                while (ModuleNext(ttapi, &module_entry))
                {
                  modulesArray.push_back(module_entry.hModule);
                  module_entry.dwSize = sizeof(MODULEENTRY32);
                }
              }
              CloseHandle(ttapi);
            }
          }
          FreeLibrary(hModule);
        }
      }

      //Check for module we are loaded to
      std::sort(modulesArray.begin(), modulesArray.end());

      //std::upper_bound
      std::vector<HMODULE>::const_iterator iPos;
      iPos = std::find_if(modulesArray.begin(), modulesArray.end(), 
        std::bind2nd(std::greater<HMODULE>(), (HMODULE)GetLog));

      //find modult with address creater than log entry point located
      //so prevous module - is container for our code
      HANDLE module = NULL;
      if (iPos != modulesArray.end() && iPos != modulesArray.begin())
        module = *(--iPos);

      TCHAR Buff[MAX_PATH] = {0};
      GetModuleFileName((HINSTANCE)module, Buff, MAX_PATH);
      return std::basic_string<TCHAR>(Buff);
    }
#endif
  public:
    inline void Write(const CharType* s, size_t len)
    {
      assert(len);
      if (_file)
        fwrite(s, sizeof(CharType), len, _file);
      return;
    }
  private:
    FILE* _file;
  };

  ////////////////////////////////////////////////////////////////////////////////////////////
  //

  template<class CharType>
  class LogWriter : public LogImpl<CharType>
  {
  protected:
    virtual void Write(const CharType* s, size_t len)
    {
      if (!len)
        return ;
#ifndef NODEBUGOUT
      WriteToDebug(s, len);
#endif
      File.Write(s, len);
    }
  private:
    inline void WriteToDebug(const char* s, size_t len)
    {
#ifdef _WIN32
      ::OutputDebugStringA(std::string(s, len).c_str());
#else
      fwrite(s, 1, len, stderr);
#endif      
    }
    inline void WriteToDebug(const wchar_t* s, size_t len)
    {
#ifdef _WIN32
      ::OutputDebugStringW(std::wstring(s, len).c_str());
#else
      fwrite(s, sizeof(wchar_t), len, stderr);
#endif      
    }
    
  private:
    FileWriter<CharType> File;
  };

  ////////////////////////////////////////////////////////////////////////////////////////////

  typedef Log<TCHAR> tLog;
  
  inline tLog* Where(tLog* log, const char* file, int line)
  {
    log->WriteLog(__T("%hs(%d) : "), file, line);
    return log;
  }

  inline tLog* Time(tLog* log)
  {
    tm loctime;
    time_t t = time(NULL);
#if _MSC_VER >= 1400
    localtime_s(&loctime, &t);
#else
    localtime_r(&t, &loctime);
#endif
    log->WriteLog(__T("[%d:%d:%d] "), loctime.tm_hour, loctime.tm_min, loctime.tm_sec);
    return log;
  }

  inline tLog* Err(tLog* log)
  {
    log->WriteLog(__T("[ERR] "));
    return log;
  }

  inline tLog* Dbg(tLog* log)
  {
    log->WriteLog(__T("[DBG] "));
    return log;
  }


  //////////////////////////////////////////////////////////////////////////
  //Define target, where log will be written

#ifdef USELOGS 
  tLog* GetLog();
  //Lock log befor entry write and unlock it when log is completed
# define DEFINE_LOG namespace Debug {tLog* GetLog(){static LogWriter<TCHAR> log; log.Lock(); return &log;}}
# define LOG(log) Debug::Time(Debug::Where(log, __FILE__, __LINE__))
# define __Error Debug::Dbg(LOG(Debug::GetLog()))->Trace
# define __Debug Debug::Err(LOG(Debug::GetLog()))->Trace
#else
# define DEFINE_LOG
  inline void _dbg_stub(const TCHAR*, ...) {}
# define __Error Debug::_dbg_stub
# define __Debug Debug::_dbg_stub
#endif
};

#endif//LOG_H

