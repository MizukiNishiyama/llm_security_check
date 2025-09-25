 void func_0(void) {
  size_t sVar1;
  FILE *pFVar2;
  char *pcVar3;
  char local_7c [100];
  long local_18;
  
  local_18 = *(long *)PTR____stack_chk_guard_100004000;
  _memset(local_7c,0,100);
  local_7c[0] = 'l';
  local_7c[1] = 0x73;
  local_7c[2] = 0x20;
  sVar1 = _strlen(local_7c);
  if ((1 < 100 - sVar1) && (pFVar2 = _fopen("/tmp/file.txt","r"), pFVar2 != (FILE *)0x0)) {
    pcVar3 = _fgets(local_7c + sVar1,100 - (int)sVar1,pFVar2);
    if (pcVar3 == (char *)0x0) {
      func_3("fgets() failed");
      local_7c[sVar1] = '\0';
    }
    _fclose(pFVar2);
  }
  func_2(local_7c);
  if (*(long *)PTR____stack_chk_guard_100004000 == local_18) {
    return;
  }
                    
  ___stack_chk_fail();
}