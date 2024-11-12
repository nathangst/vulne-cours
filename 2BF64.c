
int validate_user_login(char *username,char *pwd_key,char *auth_details,int flag)

{
  bool bVar1;
  int status_code;
  FILE *pFVar2;
  size_t sVar3;
  size_t sVar4;
  char *pcVar5;
  int iVar6;
  long timeout_value;
  char *__nptr;
  char temp_key [100];
  char decoded_data [100];
  char encoded_data [100];
  char user_password [100];
  undefined2 user_type;
  undefined2 gui_user;
  undefined2 gui_password;
  undefined2 nvram_data1;
  undefined2 nvram_data2;
  
  memset(user_password,0,100);
  memset(encoded_data,0,100);
  memset(decoded_data,0,100);
  user_type = 0;
  gui_user = 0;
  gui_password = 0;
  nvram_data1 = 0;
  nvram_data2 = 0;
  memset(temp_key,0,100);
  sscanf(auth_details,"%[^,],%[^,],%[^\n]",&user_type,encoded_data,user_password);
  if (flag == 0) {
    status_code = strncmp(encoded_data,"enc=",4);
    if (status_code != 0) {
      strcpy(decoded_data,encoded_data);
      strcpy(temp_key,pwd_key);
      goto LAB_0002c264;
    }
    process_encoded_data(pwd_key,temp_key);
    sscanf(encoded_data,"enc=%s",decoded_data);
    if (debug != 0) goto LAB_0002c07c;
LAB_0002c278:
    sVar3 = strlen(user_password);
    sVar4 = strlen(username);
    if (sVar3 != sVar4) goto LAB_0002c294;
  }
  else {
    status_code = strncmp(encoded_data,"enc=",4);
    if (status_code == 0) {
      sscanf(encoded_data,"enc=%s",decoded_data);
    }
    else {
      process_encoded_data(encoded_data,decoded_data);
    }
    strcpy(temp_key,pwd_key);
LAB_0002c264:
    if (debug == 0) goto LAB_0002c278;
LAB_0002c07c:
    pFVar2 = fopen("/dev/console","w");
    if (pFVar2 == (FILE *)0x0) goto LAB_0002c278;
    fprintf(pFVar2,"%s(): \n =========>valid user: nv_user=%s, gui_user=%s, gui_pwd=%s, nv_pwd=%s\n"
            ,"valid_user",user_password,username,temp_key,decoded_data);
    fclose(pFVar2);
    sVar3 = strlen(user_password);
    sVar4 = strlen(username);
    if (sVar3 != sVar4) goto LAB_0002c294;
  }
  sVar3 = strlen(decoded_data);
  sVar4 = strlen(temp_key);
  if ((((sVar3 != sVar4) || (status_code = strcmp(user_password,username), status_code != 0)) ||
      (status_code = strcmp(decoded_data,temp_key), status_code != 0)) ||
     ((status_code = nvram_match("en_guest",&DAT_00089a4c), status_code != 0 &&
      (status_code = nvram_match("http_power","r"), status_code != 0)))) {
LAB_0002c294:
    status_code = log_failed_login_attempt(username);
    if (status_code != 0) {
      syslog(6,"Web management login failed, user=%s\n",username);
      status_code = 0;
    }
    return status_code;
  }
  status_code = get_current_user_status();
  pcVar5 = (char *)nvram_get("auth_time");
  if (pcVar5 == (char *)0x0) {
    pcVar5 = "";
  }
  iVar6 = nvram_match("http_power",&DAT_00081240);
  if (iVar6 == 0) {
LAB_0002c17c:
    timeout_value = atol(pcVar5);
    if ((status_code < timeout_value) || (iVar6 <= status_code - timeout_value)) {
      syslog(6,"Administrator session timeout.");
      bVar1 = true;
      goto LAB_0002c1ac;
    }
  }
  else {
    __nptr = (char *)nvram_get("admin_timeout");
    if (__nptr == (char *)0x0) {
      __nptr = "";
    }
    iVar6 = atoi(__nptr);
    if (iVar6 != 99) {
      iVar6 = iVar6 * 0x3c;
      goto LAB_0002c17c;
    }
  }
  bVar1 = false;
LAB_0002c1ac:
  status_code = nvram_match("auth_st",&DAT_000899d8);
  if (((status_code == 0) ||
      (status_code = nvram_match("http_power",&DAT_00081240), status_code == 0)) || (bVar1)) {
    nvram_set("http_power",&user_type);
    pcVar5 = (char *)nvram_get("session_key");
    if (pcVar5 == (char *)0x0) {
      pcVar5 = "";
    }
    status_code = 1;
    FUN_0001f8fc(pcVar5,&DAT_000816f4);
  }
  else {
    status_code = strcmp((char *)&user_type,"rw");
    if (status_code == 0) {
      pcVar5 = (char *)nvram_get("session_key");
      if (pcVar5 == (char *)0x0) {
        pcVar5 = "";
      }
      nvram_set("tmp_auth_key",pcVar5);
      pFVar2 = fopen("/dev/console","w");
      if (pFVar2 != (FILE *)0x0) {
        fwrite("If you want to close the other session, please click on \'Continue\' button. Click \ 'Cancel\' to Logout.\n"
               ,1,0x65,pFVar2);
        fclose(pFVar2);
      }
      status_code = 3;
    }
    else {
      pFVar2 = fopen("/dev/console","w");
      if (pFVar2 != (FILE *)0x0) {
        fwrite("Administrator already logged in. You cannot login using Guest account.\n",1,0x47,
               pFVar2);
        fclose(pFVar2);
      }
      status_code = 2;
    }
  }
  syslog(6,"Web management login success, user=%s\n",username);
  return status_code;
}

