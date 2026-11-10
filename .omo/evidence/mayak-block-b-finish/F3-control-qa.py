import pathlib,subprocess,tempfile,os,ssl,http.server,threading,shlex,json,hashlib,socket,shutil
E=pathlib.Path('/home/goose/Documents/Mayak/.omo/evidence/mayak-block-b-finish')
ROOT=pathlib.Path('/home/goose/Documents/Mayak-wt/block-b-final')
results=[];children=[];upstream=None
with (E/'F3-real-manual-qa.log').open('a') as log, tempfile.TemporaryDirectory(prefix='mayak-f3-ctrl-') as tmp:
 tmp=pathlib.Path(tmp)
 def emit(s): log.write(s+'\n');log.flush();print(s,flush=True)
 def run(args,**kw):
  emit('\nSURFACE=OS/HTTP/TLS EXACT_INVOCATION='+shlex.join(args))
  r=subprocess.run(args,capture_output=True,text=True,timeout=25,**kw)
  emit('STDOUT:\n'+r.stdout+'STDERR:\n'+r.stderr+'EXIT_CODE='+str(r.returncode));return r
 def record(name,ok,**kw):
  results.append(dict(id=name,verdict='PASS' if ok else 'FAIL',**kw));emit('SCENARIO '+name+' '+results[-1]['verdict'])
 try:
  for args in [['mount','--make-rprivate','/'],['ip','link','set','lo','up'],['ip','addr','add','93.184.216.34/32','dev','lo']]:
   assert run(args).returncode==0
  (tmp/'hosts').write_text('127.0.0.1 localhost\n93.184.216.34 www.google.com\n')
  assert run(['mount','--bind',str(tmp/'hosts'),'/etc/hosts']).returncode==0
  assert run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(tmp/'key.pem'),'-out',str(tmp/'cert.pem'),'-days','1','-subj','/CN=www.google.com','-addext','subjectAltName=DNS:www.google.com']).returncode==0
  shutil.copyfile(ROOT/'targets/targets.signed.json',tmp/'targets.signed.json')
  emit('FIXTURE: temporary byte-identical copy of owner-signed targets list; isolated user/mount/network namespace; public upstream IP assigned only inside namespace; SSL_CERT_FILE trusts temporary local upstream certificate.')
  body=b'F3 local deterministic upstream\n'
  class Handler(http.server.BaseHTTPRequestHandler):
   def do_GET(self):
    self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
   def log_message(self,*args):pass
  upstream=http.server.ThreadingHTTPServer(('93.184.216.34',443),Handler)
  ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(tmp/'cert.pem',tmp/'key.pem');upstream.socket=ctx.wrap_socket(upstream.socket,server_side=True)
  thread=threading.Thread(target=upstream.serve_forever,daemon=True);thread.start()
  env=os.environ.copy();env['SSL_CERT_FILE']=str(tmp/'cert.pem');env['GODEBUG']='netdns=go';env['HTTP_PROXY']='';env['HTTPS_PROXY']='';env['ALL_PROXY']=''
  args=[str(E/'F3-mayak-ctrl.tmp'),'--addr','127.0.0.1:18443','--tls-addr','127.0.0.1:19443','--targets',str(tmp/'targets.signed.json')]
  emit('\nSURFACE=CONTROL BINARY EXACT_INVOCATION=SSL_CERT_FILE='+str(tmp/'cert.pem')+' GODEBUG=netdns=go '+shlex.join(args))
  proc=subprocess.Popen(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=env);children.append(proc)
  startup=proc.stderr.readline();emit('CONTROL_STARTUP='+startup)
  r=run(['openssl','s_client','-connect','127.0.0.1:19443','-servername','arbitrary-f3.example','-brief'],input='')
  record('any-sni',r.returncode==0 and 'CONNECTION ESTABLISHED' in r.stderr)
  def curl(name,path,status,expect=None):
   r=run(['curl','-i','--noproxy','*','--max-time','15','http://127.0.0.1:18443'+path]);ok=r.returncode==0 and r.stdout.startswith('HTTP/1.1 '+str(status)+' ')
   data=r.stdout.split('\n\n',1)[1] if '\n\n' in r.stdout else ''
   if expect is not None:ok=ok and expect(data)
   record(name,ok);return r
  curl('ping','/v1/ping',200,lambda b:b=='')
  curl('reach','/v1/reach?host=www.google.com',200,lambda b:json.loads(b)=={'reachable':True})
  expected={'status':200,'size':len(body),'body_hash':hashlib.sha256(body).hexdigest()}
  emit('UPSTREAM_BODY='+repr(body)+' EXPECTED_FETCH='+json.dumps(expected))
  curl('fetch-root','/v1/fetch?host=www.google.com&path=/',200,lambda b:json.loads(b)==expected)
  curl('fetch-robots','/v1/fetch?host=www.google.com&path=/robots.txt',200,lambda b:json.loads(b)==expected)
  curl('forbidden-ip','/v1/reach?host=www.google.com&ip=10.22.33.44',400,lambda b:'10.22.33.44' not in b)
  curl('forbidden-port','/v1/fetch?host=www.google.com&path=/&port=22',400)
  curl('bad-path','/v1/fetch?host=www.google.com&path=/etc/passwd',400)
  curl('unknown-host','/v1/reach?host=untrusted-f3.example',400)
  curl('malformed-query','/v1/fetch?host=www.google.com&path=/&ip=%ZZ',400)
  # Real plaintext client to the TLS-only listener.
  emit('SURFACE=TCP EXACT_INVOCATION=socket.create_connection((127.0.0.1,19443)); sendall(b"GET / HTTP/1.1\\r\\nHost: arbitrary-f3.example\\r\\n\\r\\n"); recv(4096)')
  with socket.create_connection(('127.0.0.1',19443),timeout=5) as s:
   s.sendall(b'GET / HTTP/1.1\r\nHost: arbitrary-f3.example\r\n\r\n')
   try:data=s.recv(4096)
   except ConnectionResetError:data=b''
  emit('TLS_PLAINTEXT_RESPONSE='+repr(data));record('tls-no-http',not data)
  statuses=[]
  for i in range(21):
   r=run(['curl','-i','--noproxy','*','--max-time','5','http://127.0.0.1:18443/v1/ping']);statuses.append(r.stdout.splitlines()[0])
  record('rate-limit',any('429' in v for v in statuses))
 finally:
  for proc in children:
   proc.terminate();out,err=proc.communicate(timeout=10)
   control_log=startup+out+err
   (E/'F3-control-node.log').write_text(control_log)
   emit('TEARDOWN control PID='+str(proc.pid)+' EXIT_CODE='+str(proc.returncode)+' COMPLETE_NODE_LOG:\n'+control_log)
   record('privacy',all(s not in control_log for s in ['127.0.0.1','10.22.33.44','arbitrary-f3.example']))
  if upstream:
   upstream.shutdown();upstream.server_close();thread.join(timeout=5);emit('TEARDOWN upstream stopped; thread_alive='+str(thread.is_alive()))
  for host,port in [('127.0.0.1',18443),('127.0.0.1',19443),('93.184.216.34',443)]:
   with socket.socket() as s:
    code=s.connect_ex((host,port));emit('TEARDOWN connect_ex '+host+':'+str(port)+' = '+str(code));record('port-closed-'+str(port),code!=0)
  (E/'F3-control-results.json').write_text(json.dumps(results,indent=2)+'\n')
 emit('TEARDOWN temporary fixture directory scheduled for automatic removal: '+str(tmp))
