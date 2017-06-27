/*{
    "window.zoomLevel": 0,
    "files.autoSave": "off"
} > mipsel-openwrt-linux-gcc udpTrClient.c -L./ -luci -lubox  -o udpreport
 ************************************************************************/
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <netdb.h>
#include <stdarg.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/ipc.h>


#define SERVER_PORT 9998

#define BUFFER_SIZE 1200
#define FILE_NAME_MAX_SIZE 512

#define MAXBUF 1500
#define DEV_SIZE 6
#define APP_VERSION 1
#define SERVER_IP "192.168.2.198" //sintai

typedef struct
{
  char devid[DEV_SIZE];
  int version;
  int id;
  int bufsize;
  char data[BUFFER_SIZE];
} SendPack;

typedef struct
{
  char devid[12];
  int version;
  int id;
  int bufsize;
  char data[BUFFER_SIZE]; //包含 RealTimeDate WirelessDates  NetworkDate
} RecvPack;

typedef struct
{
  char tr069state;       //tr069状态
  char cputype;          //cpu类型  1：mt7620 2：mt7628 3:ar9341
  char connectnum;       //客户端连接数量
  char aprouter;         //ap router类型  1：ap 2：router
  char equipment[16];    //硬件型号：FQa10-Tb
  char hardwaretype[16]; //设备厂家：FQ
  char softwaretype[16]; //软件版本：HBUCC-v1.7.013
  char portstate[8];     //port状态:1:连接 0：未连接
  int cpuload;           //系统负载：10 表示10%
  int memload;           //内存利用率：10 表示10%
  int upflow;            //上行流量
  int downflow;          //下行流量
  int uptime;            //在线时长'
} RealTimeDate;

typedef struct
{
  char ssid[30];
  char password[30];
  int encryption;
  int channel;
  int portel;
  int disabled;
} WirelessDate;

typedef struct
{
  int wifinum;
  WirelessDate wifidata[2];
} WirelessDates;

typedef struct
{
  int mode;
  char username[50];
  char password[50];
  char ipaddr[20];
  char network[20];
  char gateway[20];
  char dns1[20];
  char dns2[20];
} NetworkDate;

typedef struct
{
  int enable;
  int ipaddr;
  int port;
} TcpdumpData;


void trim(char *strIn, char *strOut){

    char *start, *end, *temp;//定义去除空格后字符串的头尾指针和遍历指针

    temp = strIn;

    while (*temp == ' '){
        ++temp;
    }

    start = temp; //求得头指针

    temp = strIn + strlen(strIn) - 1; //得到原字符串最后一个字符的指针(不是'\0')

    while (*temp == ' '||*temp == '\n'){
        --temp;
    }

    end = temp; //求得尾指针


    for(strIn = start; strIn <= end; ){
        *strOut++ = *strIn++;
    }

    *strOut = '\0';
}

void getValue(char * keyAndValue, char * key, char * value){

    char *p = keyAndValue;

    p = strstr(keyAndValue, key);
    if(p == NULL){
        //printf("没有key\n");
        return ;
    }

    p += strlen(key);
    trim(p, value);

    p = strstr(value, "=");
    if(p == NULL){
        printf("没有=\n");
        return;
    }
    p+= strlen("=");
    trim(p, value);

    p = strstr(value, "=");
    if(p != NULL){
        printf("多余的=\n");
        return;
    }
    p = value;
    trim(p, value);

}
int writeCFG(const char *filename/*in*/, const char *key/*in*/, const char *value/*in*/){
    int flen=8 * 1024;
    FILE *pf = NULL;
    char ftemp[1024] = {0}, fline[1024] = {0}, *fp;    //文件缓存数组
    long fsize = 0;
    int reg = 0;
    int exit = 0;
    int i = 0;

    pf = fopen(filename, "r+");
    if(pf == NULL){
        pf = fopen(filename, "w+");
    }
    //获得文件大小
    fseek(pf, 0, SEEK_END); // 将文件指针指向末尾
    fsize = ftell(pf);
    if(fsize > flen){
        printf("文件不能超过8k\n");
        reg = -1;
        goto end;
    }
    fseek(pf, 0, SEEK_SET); //将文件指针指向开头

    //一行一行的读，如果存在key则修改value存到缓存数组中
       while( fgets(fline, 1024, pf)!=NULL){
printf("jiangyibo2 %s\n",fline);
        if(strstr(fline, key) != NULL && exit == 1)
            strcpy(fline, "");
        if(strstr(fline, key) != NULL && exit == 0){ //判断key是否存在
            exit = 1;
            sprintf(fline,"%s = %s\n", key, value);
            printf("jiangyibo1 %s",fline);
        }

        printf("fline = %s\n", fline);
        strcat(ftemp, fline);

    }
    if(exit != 1){//如果不存在则把key value写入到最后一行
        sprintf(fline,"%s = %s\n", key, value);
        strcat(ftemp, fline);
    }
   printf("jiangyibo %s",ftemp);
    if(pf != NULL){
        fclose(pf);
        pf = fopen(filename, "w+");
         fwrite(ftemp, 1, strlen(ftemp), pf);
/*        fp = (char *)malloc(sizeof(char) * strlen(ftemp) + 1);
        strcpy(fp, ftemp);
        fp[strlen(fp) - 1] = EOF;
        fputs(fp, pf);
        if(fp != NULL){
            free(fp);
            fp = NULL;
        }
        //fclose(pf);*/
    }
    end :
        if(pf != NULL)
            fclose(pf);
    //重新创建一个以filename命名的文件
    return reg;
}

void readCFG(const char *filename/*in*/, const char *key/*in*/, const char **value/*out*/){

    FILE *pf = NULL;
    char line[1024] = {0}, vtemp[1024] = {0};

    pf = fopen(filename, "r"); //以只读方式打开
    if(pf==NULL)
    {
      return;
    }

    while(!feof(pf)){
        fgets(line, 1024, pf);
        getValue(line, key, vtemp);
        if(strlen(vtemp) != 0)
            break;
    }
    if(strlen(vtemp) != 0){
        *value = (char *)malloc(sizeof(char) * strlen(vtemp) + 1);
        strcpy(*value, vtemp);
    }
    else
        *value = NULL;
    if(pf != NULL)
        fclose(pf);
}


char device_mac[6];

pid_t getPidByName(char *name)
{
  FILE *fp;
  char n = 0;
  pid_t pid = -1;
  char buf[10] = "";
  fp = popen(name, "r");
  if (fp != NULL)
  {
    if ((fgets(buf, 6, fp)) == NULL)
    {
      pclose(fp);
      return (pid);
    }
    pclose(fp);
    pid = atoi(buf);
  }
  return (pid);
} /* end of getpidbyname */

int read_mac()
{
  FILE *fp = NULL;
  char ch;
  char bufexe[128];
  char buffstr[4096];

  if ((fp = fopen("/dev/mtdblock2", "r")) == NULL)
  {
    printf("file cannot be opened/n");
  }
  fgets(buffstr, 32, fp);
//  printf("jiang %02X %02X %02X %02X %02X %02X\n", buffstr[4], buffstr[5], buffstr[6], buffstr[7], buffstr[8], buffstr[9]);

  device_mac[0] = buffstr[4];
  device_mac[1] = buffstr[5];
  device_mac[2] = buffstr[6];
  device_mac[3] = buffstr[7];
  device_mac[4] = buffstr[8];
  device_mac[5] = buffstr[9];
  fclose(fp);
  fp = NULL;

  return 0;
}

static void sigHandle(int sig, struct siginfo *siginfo, void *myact)
{

  //printf("sig=%d siginfo->si_int=%d SIGALRM=%d,SIGSEGV=%d\n",sig,siginfo->si_int,SIGALRM,SIGSEGV);
  if (sig == SIGALRM)
  {
  }
  else if (sig == SIGSEGV)
  {
    sleep(1);
  }
}

static void sigInit()
{
  int i;
  struct sigaction act;
  sigemptyset(&act.sa_mask);
  act.sa_flags = SA_SIGINFO;
  act.sa_sigaction = sigHandle;

  sigaction(SIGALRM, &act, NULL);
  sigaction(SIGSEGV, &act, NULL);
}

char cliBuff[1024];

char *exeShell(char *comm)
{
  FILE *fstream = NULL;

  int errnoT = 0;

  memset(cliBuff, 0, sizeof(cliBuff));

  if (NULL == (fstream = popen(comm, "r")))
  {
    fprintf(stderr, "execute command failed: %s", strerror(errno));
    return "error";
  }
  /*    if(NULL!=fread(cliBuff,1, sizeof(cliBuff), fstream))    
    {    
        printf("exeShell zhi\n");   
    }    
    else   
    {   
        pclose(fstream);   
        return cliBuff;   
    }   
    */
  pclose(fstream);

  return cliBuff;
}

int getCpuUsage()
{
  float sys_usage;
  float user_usage;
#define CPU_FILE_PROC_STAT "/proc/stat"
  FILE *fp = NULL;
  char tmp[10];
  unsigned long user, sys, nice, idle, total;

  fp = fopen(CPU_FILE_PROC_STAT, "r");
  if (fp == NULL)
  {
    return 10;
  }
  fscanf(fp, "%s %lu %lu %lu %lu", tmp, &user, &nice, &sys, &idle);

  fclose(fp);
  total = user + sys + nice + idle;
  if (total > 0)
  {
    sys_usage = sys * 100.0 / total;
    user_usage = user * 100.0 / total;
    return (int)((sys_usage+user_usage));
  }
  else
  {
    sys_usage = 0;
    user_usage = 0;
    return 10;
  }
  //cpu_rate = (1-idle/total)*100;
 
  return 0;
}

struct mem_usage_t
{
  unsigned long total;
  unsigned long used;
  unsigned long free;
  unsigned long shared;
  unsigned long buffers;
  unsigned long cached;
};

int getMemUsage()
{
  FILE *fp = NULL;
  struct mem_usage_t memge;
  struct mem_usage_t *usage;
  usage = &memge;
  char tmp[1024];
  char str[128];
  char str1[128];
  int total=0,memfree=0;
  int index = 0;
  char *t;

  fp = fopen("/proc/meminfo", "r");
  if (fp == NULL)
  {
    return 10;
  }
  
    while ((fgets(tmp, 1024, fp)) != NULL)
    {
       if(strstr(tmp,"MemTotal:"))
       {
          index = 0;
          t = strtok(tmp, " ");  
            while(t != NULL){  
              index++;
                  if(index==2)
                  {
                     total = atoi(t);
                   //  printf("%s\n", t);  
                  }
                  t = strtok(NULL, " ");  
            } 
         
       }
       else if(strstr(tmp,"MemFree:"))
       {
                    index = 0;
          t = strtok(tmp, " ");  
            while(t != NULL){  
              index++;
                  if(index==2)
                  {
                  //   printf("%s\n", t);  
                     memfree = atoi(t);
                  }
                  t = strtok(NULL, " ");  
            } 
       }
       else {

         break;
       }

    }
 // printf("jiangyibo mem %d \n",(int)((memfree*100.0)/total));

  return (int)((memfree*100.0)/total);
}

int getRunTime()
{

  FILE *fp = NULL;
  char tmp[128];
  int timeBuf = 0;

  fp = popen("cat /proc/uptime | awk -F \".\" '{ print $1 }'", "r");
  if (fp == NULL)
  {
    return 0;
  }
  if ( fread(tmp, 1, 128, fp)>0)
  {
    timeBuf = atoi(tmp);
  }
  else
  {
  }
  pclose(fp);
//  printf("jiangyibo getRunTime %d\n", timeBuf);
  return timeBuf;
}

int getPortState(char *portstate)
{

  FILE *fp = NULL;
  char tmp[1024];
  int timeBuf = 0;
  char *port = portstate;
  int i;

  int portResult = 0;

  fp = popen("swconfig dev switch0 show 2>/dev/null", "r");
  if (fp == NULL)
  {
    return 0;
  }

  while ((fgets(tmp, 1024, fp)) != NULL)
  {
    if (strstr(tmp, "link: port:0 link:up"))
    {
      port[0] = 1;
    }
    else if (strstr(tmp, "link: port:1 link:up"))
    {
      port[1] = 1;
    }
    else if (strstr(tmp, "link: port:2 link:up"))
    {
      port[2] = 1;
    }
    else if (strstr(tmp, "link: port:3 link:up"))
    {
      port[3] = 1;
    }
    else if (strstr(tmp, "link: port:4 link:up"))
    {
      port[4] = 1;
    }
  }

  pclose(fp);

  return portResult;
}

int getDeviceSpeed(int *total, int *used)
{

  FILE *fp = NULL;
  char tmp[128];
  int timeBuf = 0;

  fp = popen("ifconfig br-lan|grep bytes|awk -F 'bytes:' '{print $2,$3}'|awk '{print $1,$5}'", "r");
  if (fp == NULL)
  {
    return 0;
  }
  fscanf(fp, "%lu %lu", total,used);
//  printf("jiangyibo getRunTime %d %d\n", *total, *used);
  pclose(fp);
  return 0;
}

int getConnectNum(char *conn)
{

  FILE *fp = NULL;
  char tmp[128];
  int timeBuf = 0;
  int total;

  fp = popen("iwinfo ra0 a|grep RX|wc -l", "r");
  if (fp == NULL)
  {
    return 0;
  }
  fscanf(fp, "%lu", &total);
//  printf("jiangyibo getConnectNum %d\n", total);
  pclose(fp);
  *conn = (char)total;
  return 0;
}


int spilt_string(char *string)
{
  int i = 0;
  const char *split = " ";
  char *p;

  p = strtok(string, split);
  while (p)
  {
    if (i == 1)
    {
      strcpy(string, p);
      //printf(" is : %s \n",string);
      return 0;
    }
    i++;
    p = strtok(NULL, split);
  }
  return -1;
}

int find_position(char *find)
{
  FILE *fp;
  char *p, buffer[128] = {0}; //初始化
  int ret;

  fp = fopen("/etc/config/wireless", "r");
  if (fp < 0)
  {
    printf("open file failed.\n");
    return -1;
  }

  //memset(buffer, 0, sizeof(buffer));
  fseek(fp, 0, SEEK_SET);
  while (fgets(buffer, 128, fp) != NULL)
  {
    p = strstr(buffer, find);
    if (p)
    {
      // printf("string is :%s \n",p);
      ret = spilt_string(p);
      if (ret == 0)
      {
        memset(find, 0, sizeof(find));
        strncpy(find, p, sizeof(p));
        return 0;
      }
    }
    memset(buffer, 0, sizeof(buffer));
  }

  fclose(fp);
  return -1;
}

int get_ower()
{
  char find[] = "Power";
  int ret;
  ret = find_position(&find);
  printf("ower --> %s", find);

  return 0;
}



int main(int argc, char *argv[])
{
//  read_mac();
  

  int id = 0;
  SendPack sendmsg;
  int index = 0;
  char *p;
  char key[1024] = {0};
  char *reportip=NULL;
  RealTimeDate *pReal;
  WirelessDates *pWireless;
  NetworkDate *pNet;
  sigInit();

  
   readCFG("/etc/report.conf"/*in*/,"reportip", &reportip/*out*/);
   
    if(reportip != NULL){
         printf("reportip %s\n",reportip);
         printf("reportip ok\n");
     }else{
       writeCFG("/etc/report.conf","reportip",SERVER_IP);
     }


  pReal = sendmsg.data;
  pWireless = sendmsg.data + sizeof(RealTimeDate);
  pNet = sendmsg.data + sizeof(RealTimeDate) + sizeof(WirelessDates);

  sendmsg.version = APP_VERSION;
  sendmsg.id = 222;
  memcpy(sendmsg.devid, device_mac, 6);
  sendmsg.bufsize = 1500;
  sprintf(pReal->equipment, "SINTAI");
  sprintf(pReal->hardwaretype, "PF308-TZ-H");
  sprintf(pReal->softwaretype, "1.6.12");

  pReal->aprouter = 1;
  pWireless->wifinum = 1;

  sendmsg.version = APP_VERSION;

  /* 服务端地址 */
  struct sockaddr_in server_addr;
  bzero(&server_addr, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  if (argc == 1&&reportip!=NULL)
  {
    server_addr.sin_addr.s_addr = inet_addr(reportip);
  }
  else if (argc == 2)
  {
    server_addr.sin_addr.s_addr = inet_addr(argv[1]);
  }
  else 
  {
    server_addr.sin_addr.s_addr = inet_addr(SERVER_IP);
  }
  server_addr.sin_port = htons(SERVER_PORT);
  socklen_t server_addr_length = sizeof(server_addr);

  /* 创建socket */
  int client_socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (client_socket_fd < 0)
  {
    perror("Create Socket Failed:");
    exit(1);
  }

   if(reportip != NULL){
         free(reportip);
         reportip = NULL;
     }

  struct timeval timeout = {5, 0};
  setsockopt(client_socket_fd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(struct timeval));
  setsockopt(client_socket_fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(struct timeval));

  RecvPack pack_info;

  int len = 0;
  int temp = 1;
  int inSpeed = 0, outSpeed = 0;
  int looptimes = 10;
  while (1)
  {
  //  printf("jiangyibo while\n");
    if (getPidByName("pidof freecwmpd") < 1)
      pReal->tr069state = 4;
    else
      pReal->tr069state = 3;
     if(looptimes++ >= 10 )
     {
       looptimes = 0;
      pReal->cpuload = getCpuUsage();
      pReal->memload = getMemUsage();

      pReal->uptime = getRunTime();
      pReal->cputype = 1;

     }



    printf("jiangyibo send 111 ok\n");
    if (sendto(client_socket_fd, (char *)&sendmsg, sizeof(SendPack), 0, (struct sockaddr *)&server_addr, server_addr_length) < 0)
    {
      printf("Send Failed:\n");
      // exit(1);
    }
    /* 从服务器接收数据，并写入文件 */
    if ((len = recvfrom(client_socket_fd, (char *)&pack_info, sizeof(pack_info), 0, (struct sockaddr *)&server_addr, &server_addr_length)) > 0)
    {
      p = (char *)&pack_info;
      for (index = 0; index < 14; index++)
      {
        printf("%d", p[index]);
      }
      printf("jiangyibo recvs %d\n", pack_info.id);
      if (pack_info.id == 3)
      {
        if (pReal->tr069state == 4)
        {
          exeShell("/etc/init.d/freecwmpd start&");
        }
      }
      else if (pack_info.id == 4)
      {
        if (pReal->tr069state == 3)
        {
          exeShell("/etc/init.d/freecwmpd stop&");
        }
      }
      else if (pack_info.id == 5)
      {
        if (pReal->tr069state == 3)
        {
          exeShell("/etc/init.d/freecwmpd stop&");
        }
      }
      else if (pack_info.id == 6)
      {
        if (pack_info.data[0] == 3)
        {
          system("reboot -f");
        }
      }
      else if (pack_info.id == 7)
      {
        if (pack_info.data[0] == 3)
        {
          system("");
        }
      }
     else if (pack_info.id == 8)
      {
        if (pack_info.data[0] == 3)
        {
          system("/usr/sbin/updateUdpReport.sh &");
        }
      }
      sleep(10);
    }
    else
    {
      sleep(5);
      //break;
    }
  }
  printf("cucuo \n");
  /*
  alarm(30);

  while (1)
  {	
    pause();
  }
*/

  close(client_socket_fd);
  return 0;
}
