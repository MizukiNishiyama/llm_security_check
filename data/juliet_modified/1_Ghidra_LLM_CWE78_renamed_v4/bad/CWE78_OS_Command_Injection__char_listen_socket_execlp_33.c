void CWE78_OS_Command_Injection__char_listen_socket_execlp_33::func_0(void)

{
  int iVar1;
  int iVar2;
  size_t sVar3;
  ssize_t sVar4;
  undefined1 *puVar5;
  int local_b8;
  sockaddr local_90;
  char local_7c [100];
  long local_18;
  
  local_18 = *(long *)PTR____stack_chk_guard_100004000;
  _memset(local_7c,0,100);
  local_7c[0] = 'l';
  local_7c[1] = 0x73;
  local_7c[2] = 0x20;
  local_b8 = -1;
  sVar3 = _strlen(local_7c);
  iVar1 = _socket(2,1,6);
  if (iVar1 != -1) {
    local_90.sa_data[6] = '\0';
    local_90.sa_data[7] = '\0';
    local_90.sa_data[8] = '\0';
    local_90.sa_data[9] = '\0';
    local_90.sa_data[10] = '\0';
    local_90.sa_data[0xb] = '\0';
    local_90.sa_data[0xc] = '\0';
    local_90.sa_data[0xd] = '\0';
    local_90.sa_len = '\0';
    local_90.sa_family = '\x02';
    local_90.sa_data[0] = 'i';
    local_90.sa_data[1] = -0x79;
    local_90.sa_data[2] = '\0';
    local_90.sa_data[3] = '\0';
    local_90.sa_data[4] = '\0';
    local_90.sa_data[5] = '\0';
    iVar2 = _bind(iVar1,&local_90,0x10);
    if (((iVar2 != -1) && (iVar2 = _listen(iVar1,5), iVar2 != -1)) &&
       (local_b8 = _accept(iVar1,(sockaddr *)0x0,(socklen_t *)0x0), local_b8 != -1)) {
      sVar4 = _recv(local_b8,local_7c + sVar3,99 - sVar3,0);
      iVar2 = (int)sVar4;
      if ((iVar2 != -1) && (iVar2 != 0)) {
        local_7c[sVar3 + (ulong)(long)iVar2 / 1] = '\0';
        puVar5 = (undefined1 *)func_1(local_7c,0xd);
        if (puVar5 != (undefined1 *)0x0) {
          *puVar5 = 0;
        }
        puVar5 = (undefined1 *)func_1(local_7c,10);
        if (puVar5 != (undefined1 *)0x0) {
          *puVar5 = 0;
        }
      }
    }
  }
  if (iVar1 != -1) {
    _close(iVar1);
  }
  if (local_b8 != -1) {
    _close(local_b8);
  }
  iVar1 = _execlp("sh","sh");
  if (*(long *)PTR____stack_chk_guard_100004000 != local_18) {
                    
    ___stack_chk_fail(iVar1);
  }
  return;
}