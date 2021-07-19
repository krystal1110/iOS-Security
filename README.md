# Hook  攻防

### HooK原理 ： 钩子，改变程序的执行流程的一种技术
  

---


### **MethodSwizzle **
 * 利用OC的运行时（Runtime）特性修改 `SEL` 和 `IMP(函数指针)` 的关系，打到Hook OC方法的目的
 * ` method_exchangeIMP `交换两个 `IMP`
 * ` class_replaceMethod `替换某个 ` SEL `的 `IMP` （如果没有该方法就添加，相当于换掉这个方法）
 * ` method_getImplementation ` 、` method_setImplementation ` 获取和设置某个方法的IMP （很多第三方框架都使用）

---

### fishhook
* Facebook提供的工具，利用MachO文件的加载原理，动态修改懒加载和非懒加载两个符号表！

* 可以HOOK系统的函数，但是无法HOOK自定义的函数
 #### ** 原理：**
    *  共享缓存
       * iOS系统有一块特殊的位置，存放公用动态库。动态库共享缓存（dyld shared Cache）
    *  PIC技术
       * 由于外部的函数调用，在我们编译时是没有办法确定地址的。
       * 苹果就采用PIC技术（位置无关代码），在MachO文件 ` DATA段 ` ，建立两张表，懒加载和非懒加载表，里面存放执行外部函数指针
       * 首次调用懒加载函数，回去找桩执行代码，首次执行会调用 ` dyld_bingder 函数`
       
    *  通过字符找到懒加载表
       * fishhook利用 
          - ` stirng Table 字符表` -> 
          - ` Symbols 符号表 ` -> 
          - ` indirect Symbols 间接符号表 ` -> 
          - ` Lazy Symbol 懒加载符号表中的地址值  ` 
       * 通过重绑定修改指针的值达到HOOK的目的

--- 


### Cydia Substrate
* 一个强大的框架
* 越狱后基本都会有


--- 

### MonKey Hook 
Monkey中使用了  `libsubstrate.dylib`
* `method_setImplementation`
* `method_getImplementation`

#### **MonKey已经替换的系统函数**
* dlsym 
* sysctl
* ptrace

--- 

### Dobby （修改静态函数 C 和 swift）
 * 实际上是替换 ` Text段 `   
 * 动态修改 （加载到内存的时候修改）


--- 

### 防护 ：` lldb - ptrace ` 

 *  ` ptrace ` 是 命令行工程以及 Mac OS 工程里的 ` <sys/ptrace.h> `提供的一个函数 , 可以用来来控制进程附加管理 , 它可以实现禁止应用程序进程被附加的效果 . 在 iOS 中并没有暴露出来 , 但是 iOS 是可以使用的 .
 

```C++
/**
 arg1: ptrace要做的事情: PT_DENY_ATTACH 表示要控制的是当前进程不允许被附加
 arg2: 要操作进程的PID , 0就代表自己
 arg3: 地址 取决于第一个参数要做的处理不同传递不同
 arg4: 数据 取决于第一个参数要做的处理不同传递不同
 */
ptrace(PT_DENY_ATTACH, 0, 0, 0);
```

 * 效果：
    - 运行工程 , 程序闪退 .
    - 从手机点开应用 , 应用正常 .
    - 使用Xcode 自带的 Debug - Attach to process 发现附加失败 
    
 * 破解：
    - 通过符号断点检测
    - 使用 ` fishhook `  HOOK掉ptrace这个函数


--- 
---
---
---
    
### 防护： sysctl
 - ` sysctl ( system control ) ` 是由 ` <sys/sysctl.h> ` 提供的一个函数 , 它有很多作用 , 其中一个是可以监测当前进程有没有被附加 . 但是因为其特性 , 只是监测当前时刻应用有没有被附加 .
 - 因此正向开发中我们往往结合定时器一起使用 , 或者 定时 / 定期 / 在特定时期 去使用 . 
  
```C++
#import "ViewController.h"
#import <sys/sysctl.h>
@interface ViewController ()
@end

@implementation ViewController
BOOL isDebug(){
    int name[4];             //里面放字节码。查询的信息
    name[0] = CTL_KERN;      //内核查询
    name[1] = KERN_PROC;     //查询进程
    name[2] = KERN_PROC_PID; //传递的参数是进程的ID
    name[3] = getpid();      //获取当前进程ID
    
    struct kinfo_proc info;  //接受查询结果的结构体
    size_t info_size = sizeof(info);  //结构体大小
    if(sysctl(name, 4, &info, &info_size, 0, 0)){
        NSLog(@"查询失败");
        return NO;
    }
    /**
    查询结果看info.kp_proc.p_flag 的第12位。如果为1，表示调试状态。
    (info.kp_proc.p_flag & P_TRACED) 就是0x800, 即可获取第12位
    */
    return ((info.kp_proc.p_flag & P_TRACED) != 0);
}

static dispatch_source_t timer;
void debugCheck(){
    timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, dispatch_get_global_queue(0, 0));
    dispatch_source_set_timer(timer, DISPATCH_TIME_NOW, 1.0 * NSEC_PER_SEC, 0.0 * NSEC_PER_SEC);
    dispatch_source_set_event_handler(timer, ^{
        if (isDebug()) {//在这里写你检测到调试要做的操作
            NSLog(@"调试状态!");
        }else{
            NSLog(@"正常！");
        }
    });
    dispatch_resume(timer);
}

- (void)viewDidLoad {
    [super viewDidLoad];
    debugCheck();
}

  ```
  * 效果：
    - 可以上报或者 ` exit `


  * 破解：
    - 因为 `sysctl`函数也是系统函数，从而可以使用fishHook来交换
  
```C++
int  (*sysctl_ptr)(int *, u_int, void *, size_t *, void *, size_t);

int  my_sysctl(int * name, u_int namelen, void * info, size_t * infoSize, void * newInfo, size_t newInfoSize){
    if (name[0] == CTL_KERN && name[1] == KERN_PROC && name[2] == KERN_PROC_PID && *infoSize == sizeof(struct kinfo_proc)) {
        
        int old = sysctl_ptr(name,namelen,info,infoSize,newInfo,newInfoSize);
        //拿出info
        struct kinfo_proc * myinfo = (struct kinfo_proc *)info;
        
        if ((myinfo->kp_proc.p_flag & P_TRACED ) != 0 ) {
            //使用异或取反
            myinfo->kp_proc.p_flag ^= P_TRACED;
        }
        return old;
    }
    return sysctl_ptr(name,namelen,info,infoSize,newInfo,newInfoSize);
}

+(void)load{
  
    struct rebinding rebingSysctl;
    rebingSysctl.name = "sysctl";
    rebingSysctl.replacement = my_sysctl;
    rebingSysctl.replaced = (void *)&sysctl_ptr;
    struct rebinding rebs[1] = {rebingSysctl};
    rebind_symbols(rebs, 1);
}
```
  * 注意：
    - 需要慎用 ` exit ` 函数
    - 逆向中通过 ` exit `  添加符号断点，就可以查看函数调用栈，从而可以看到调用 `exit`的函数地址，在减去首地址就可以拿到函数的偏移量，接着在 ` Hopper ` 当中就可以知道调用 `exit` 的地址了
    - 我们自己开发所使用的 ` framework` 会比注入的动态库更早的执行，虽然还是会被 ` fishhook ` 替换掉，但是可以在此之前，禁用掉 `fishhook` 或者完成检测
    - 只不过如果破解人员找到这个 `framework` ，然后在 `load` 方法中直接 ` Return `
---
---
---
---
### 防护： 通过函数地址直接调用 `ptrace` 和 `sysctl`
* 在我工程开始我就获取 ` ptrace / sysctl ` 的地址 , 后面直接使用地址调用这个函数 . 实际上是可行的 , 利用 ` dlsym `这个函数 .
    
  - 通过符号获取函数地址 ( dladdr 函数 ) 
  - 通过函数内部地址找到函数符号 ( dlsym 函数 ) 
```C++
#import "MyPtraceHeader.h"
#import <dlfcn.h>
  
void callFunAddres(void) {
    int name[4];             //里面放字节码。查询的信息
    name[0] = CTL_KERN;      //内核查询
    name[1] = KERN_PROC;     //查询进程
    name[2] = KERN_PROC_PID; //传递的参数是进程的ID
    name[3] = getpid();      //获取当前进程ID
    
    struct kinfo_proc info;  //接受查询结果的结构体
    size_t info_size = sizeof(info);  //结构体大小
    
    //这里做法是隐藏常量字符串
    unsigned char str[] = {
        ('a' ^ 's'),
        ('a' ^ 'y'),
        ('a' ^ 's'),
        ('a' ^ 'c'),
        ('a' ^ 't'),
        ('a' ^ 'l'),
        ('a' ^ '\0')
    };
    unsigned char * p = str;
    printf("%s", str);
    while (((*p) ^= 'a') != '\0') p++;
    
    void * handle = dlopen("/usr/lib/system/libsystem_c.dylib", RTLD_LAZY);

    int  (*sysctl_ptr)(int *, u_int, void *, size_t *, void *, size_t);
    //获取sysctl函数指针
    sysctl_ptr = dlsym(handle,(const char *)str);
    if (sysctl_ptr) {
        
        sysctl_ptr(name, 4, &info, &info_size, 0, 0);
      
        if ((info.kp_proc.p_flag & P_TRACED ) != 0 ){
            NSLog(@"调试状态");
        }else{
            NSLog(@"正常");
        }
    }
}
```
 * 破解 
   - 使用 ` fishhook  ` 将  ` dlopen ` 与 ` dlsym ` 这两个系统函数干掉
  
  
---
---
---
---  
### 防护 汇编   
  * 使用汇编直接调用 
  
  
  
  
---
---  
---  
### 字符串常量隐藏 
  * 例如在App内注册第三方APP的Key,SecretKey等，字符串常量隐藏

```C++
#define kWxAppID @"krystal69d7xxxxxx"  
 - (void)configureForWXSDK{
    [WXApi registerApp:kWxAppID
         universalLink:@"123123"];
}
```
利用Hopper打开MachO就可以看到  
![](https://tva1.sinaimg.cn/large/008i3skNgy1gslif4da10j31lw0egmze.jpg)  

* 解决办法
  - 在方法中返回这个字符串

```C++
#define KRYSTAL_ENCRYPT_KEY @"krystal_key"
@implementation ViewController
- (void)viewDidLoad {
    [super viewDidLoad];
    //使用函数代替字符串
    [self uploadDataWithKey:AES_KEY()];  
}

- (void)uploadDataWithKey:(NSString *)key{
    NSLog(@"%@",key);
}

static NSString * AES_KEY(){
    unsigned char key[] = {
        'k','r','y','s','t','a','l','_','k','e','y','\0',
    };
    return [NSString stringWithUTF8String:(const char *)key];
}
@end
```

*    **破解：**
     -  静态分析需要找到这个返回 ` Key` 函数 
  
* **升级防护**
   - 通过异或方式
   - 这些字符不会进入字符常量区 . 编译器直接换算成异或结果 .
```C++
#define STRING_ENCRYPT_KEY @"demo_AES_key"
#define ENCRYPT_KEY 0xAC
@interface ViewController ()
@end

@implementation ViewController
- (void)viewDidLoad {
    [super viewDidLoad];
//    [self uploadDataWithKey:STRING_ENCRYPT_KEY]; //使用宏/常量字符串
    [self uploadDataWithKey:AES_KEY()]; //使用函数代替字符串
}

- (void)uploadDataWithKey:(NSString *)key{
    NSLog(@"%@",key);
}

static NSString * AES_KEY(){
    unsigned char key[] = {
        (ENCRYPT_KEY ^ 'd'),
        (ENCRYPT_KEY ^ 'e'),
        (ENCRYPT_KEY ^ 'm'),
        (ENCRYPT_KEY ^ 'o'),
        (ENCRYPT_KEY ^ '_'),
        (ENCRYPT_KEY ^ 'A'),
        (ENCRYPT_KEY ^ 'E'),
        (ENCRYPT_KEY ^ 'S'),
        (ENCRYPT_KEY ^ '_'),
        (ENCRYPT_KEY ^ '\0'),
    };
    unsigned char * p = key;
    while (((*p) ^= ENCRYPT_KEY) != '\0') {
        p++;
    }
    return [NSString stringWithUTF8String:(const char *)key];
}
@end
```
  * **效果：**
  ![](https://tva1.sinaimg.cn/large/008i3skNgy1gsm44y5b44j30o80ka76l.jpg)
  
 ---
 ---
 ---
 
 ### 动态库检测
 * 可以在服务器上存储一份 ` _dyld_image_name`
 * 然后本地运行后获取到的上传服务器做比对
```C++
+ (BOOL)isExternalLibs{
    if(TARGET_IPHONE_SIMULATOR)return NO;
    int dyld_count = _dyld_image_count();
    for (int i = 0; i < dyld_count; i++) {
        const char * imageName = _dyld_get_image_name(i);
        NSString *res = [NSString stringWithUTF8String:imageName];
        if([res hasPrefix:@"/var/containers/Bundle/Application"]){
            if([res hasSuffix:@".dylib"]){
                //这边还需要过滤掉自己项目中本身有的动态库
                return YES;
            }
        }
    }
    return NO;
}
```

* **破解：** 
     - 可以hook NSString的hasPrefix方法绕过检测
 
 
---
---
--- 
      
### 越狱检测      
 ### 防护  NSFileManager
  * 使用NSFileManager通过检测一些越狱后的关键文件/路径是否可以访问来判断是否越狱 常见的文件/路径有
```C++
 static char *JailbrokenPathArr[] = {"/Applications/Cydia.app",
                                     "/usr/sbin/sshd",
                                     "/bin/bash",
                                     "/etc/apt",
                                     "/Library/MobileSubstrate",
                                     "/User/Applications/"}; 
      
      
+ (BOOL)isJailbroken1{
    if(TARGET_IPHONE_SIMULATOR)return NO;
    for (int i = 0;i < sizeof(JailbrokenPathArr) / sizeof(char *);i++) {
        if([[NSFileManager defaultManager] fileExistsAtPath:[NSString stringWithUTF8String:JailbrokenPathArr[i]]]){
            return YES;
        }
    }
    return NO;
}
```
 * 破解
   - 攻击者可以通过hook NSFileManager的fileExistsAtPath方法来绕过检测
```C++
//绕过使用NSFileManager判断特定文件是否存在的越狱检测，此时直接返回NO势必会影响程序中对这个方法的正常使用，因此可以先打印一下path，然后判断如果path是用来判断是否越狱则返回NO，否则按照正常逻辑返回
%hook NSFileManager
- (BOOL)fileExistsAtPath:(NSString *)path{
    if(TARGET_IPHONE_SIMULATOR)return NO;
    for (int i = 0;i < sizeof(JailbrokenPathArr) / sizeof(char *);i++) {
        NSString *jPath = [NSString stringWithUTF8String:JailbrokenPathArr[i]];
        if([path isEqualToString:jPath]){
            return NO;
        }
    }
    return %orig;
}
%end

```
---
---
---
### 防护 `stat` 函数
 * 使用C语言函数stat判断文件是否存在(注:stat函数用于获取对应文件信息，返回0则为获取成功，-1为获取失败)
```C++
+ (BOOL)isJailbroken2{
    if(TARGET_IPHONE_SIMULATOR)return NO;
    for (int i = 0;i < sizeof(JailbrokenPathArr) / sizeof(char *);i++) {
        struct stat stat_info;
        if (0 == stat(JailbrokenPathArr[i], &stat_info)) {
            return YES;
        }
    }
    return NO;
}      
```
      
* 破解：
   - 使用fishhook可hook C函数，fishhook通过在mac-o文件中查找并替换函数地址达到hook的目的
```C++
static int (*orig_stat)(char *c, struct stat *s);
int hook_stat(char *c, struct stat *s){
    for (int i = 0;i < sizeof(JailbrokenPathArr) / sizeof(char *);i++) {
        if(0 == strcmp(c, JailbrokenPathArr[i])){
            return 0;
        }
    }
    return orig_stat(c,s);
}
+(void)statHook{
    struct rebinding stat_rebinding = {"stat", hook_stat, (void *)&orig_stat};
    rebind_symbols((struct rebinding[1]){stat_rebinding}, 1);
}

```
 在动态库加载的时候，调用statHook    
```C
 %ctor{
    [StatHook statHook];
}
 ```
      
* 判断stat的来源是否来自于系统库，因为fishhook通过交换函数地址来实现hook，若hook了stat，则stat来源将指向攻击者注入的动态库中 因此我们可以完善上方的isJailbroken2判断规则，若stat来源非系统库，则直接返回已越狱      
```C++
+ (BOOL)isJailbroken2{
    if(TARGET_IPHONE_SIMULATOR)return NO;
    int ret ;
    Dl_info dylib_info;
    int (*func_stat)(const char *, struct stat *) = stat;
    if ((ret = dladdr(func_stat, &dylib_info))) {
        NSString *fName = [NSString stringWithUTF8String:dylib_info.dli_fname];
        NSLog(@"fname--%@",fName);
        if(![fName isEqualToString:@"/usr/lib/system/libsystem_kernel.dylib"]){
            return YES;
        }
    }
    
    for (int i = 0;i < sizeof(JailbrokenPathArr) / sizeof(char *);i++) {
        struct stat stat_info;
        if (0 == stat(JailbrokenPathArr[i], &stat_info)) {
            return YES;
        }
    }
    
    return NO;
}

```
---
---
---
### BundleID检测
* 进行BundleID检测可以有效防止多开
* 获取当前项目的BundleID有多种方法，此处不再赘述，绕过检测则是hook对应的方法，返回原有的BundleID
* 防止攻击者绕过检测，可以在自行link的framework中获取BundleID并进行检测，以在被hook前进行校验
 BundleID并进行校验以避免常见的BundleID获取方法被hook
```C
//获取Boundle ID
char  * bundleName =  getenv("XPC_SERVICE_NAME");
    NSLog(@"%s",bundleName);
```
      
      
      
      
      
      
      
      
      
