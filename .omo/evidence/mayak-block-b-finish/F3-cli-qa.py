import subprocess, pathlib, tempfile, os, json, shlex
ROOT=pathlib.Path('/home/goose/Documents/Mayak-wt/block-b-final')
E=pathlib.Path('/home/goose/Documents/Mayak/.omo/evidence/mayak-block-b-finish')
results=[]
with (E/'F3-real-manual-qa.log').open('a') as log, tempfile.TemporaryDirectory(prefix='mayak-f3-cli-') as tmp:
 def run(args,env=None):
  log.write('\n$ '+shlex.join(args)+'\n');log.flush()
  r=subprocess.run(args,cwd=ROOT,env=env,capture_output=True,text=True)
  log.write('STDOUT:\n'+r.stdout+'STDERR:\n'+r.stderr+'EXIT_CODE='+str(r.returncode)+'\n');log.flush()
  return r
 r=run(['python3','-c',"import yaml,json; w=yaml.safe_load(open('.github/workflows/ci.yml')); assert set(w['jobs'])=={'check','windows','release-check'}; assert w['jobs']['windows']['runs-on']=='windows-2025'; print(json.dumps(w['jobs'],indent=2))"])
 results.append(dict(id='CI',verdict='PASS' if r.returncode==0 else 'FAIL'))
 for target in ['mayak','mayak-ctrl']:
  r=run(['go','build','-o',tmp+'/'+target,'./cmd/'+target]);assert r.returncode==0
 # Copy only the finished control executable into the namespace runner's temp directory later.
 import shutil
 shutil.copyfile(tmp+'/mayak-ctrl',E/'F3-mayak-ctrl.tmp');os.chmod(E/'F3-mayak-ctrl.tmp',0o700)
 guard='mayak check: no control node is configured in this build, so nothing can be measured. Nothing was sent.\n'
 for name,args,code in [('version',['version'],0),('no-control',['check'],2),('json-no-control',['check','--json'],2),('limit',['check','--limit','3'],1)]:
  with tempfile.TemporaryDirectory(prefix='xdg-',dir=tmp) as cfg:
   env=os.environ.copy();env['XDG_CONFIG_HOME']=cfg
   invocation=[tmp+'/mayak']+args
   log.write('\nSURFACE=CLI SCENARIO='+name+' XDG_CONFIG_HOME='+cfg+'\n')
   if name=='no-control': invocation=['strace','-f','-e','trace=network','-o',str(E/'F3-no-control.strace')]+invocation
   r=run(invocation,env)
   ok=r.returncode==code
   if name=='version':ok=ok and r.stdout=='dev\n' and not r.stderr
   if name in ['no-control','json-no-control']:ok=ok and r.stdout=='' and r.stderr==guard
   if name=='no-control':
    trace=(E/'F3-no-control.strace').read_text();network=[line for line in trace.splitlines() if '(' in line]
    log.write('NETWORK_SYSCALL_LINES='+json.dumps(network)+'\n');ok=ok and not network
   results.append(dict(id=name,verdict='PASS' if ok else 'FAIL',exit_code=r.returncode,invocation=invocation))
 (E/'F3-cli-results.json').write_text(json.dumps(results,indent=2)+'\n')
 print(json.dumps(results,indent=2))
