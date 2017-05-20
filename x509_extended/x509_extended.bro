module X509EXTENDED;

export {
  redef enum Log::ID += { LOG };

  type Info: record {
    ## When the email was seen.
    ts:   time    &log;
    resp_h: addr &log;
    resp_p: port &log;
    ## Basic information about the certificate.
    cert: X509::Certificate &log;
    san: X509::SubjectAlternativeName &optional &log;
    md5: string &optional &log;
    sha1: string &optional &log;
    sha256: string &optional &log;
  };

  const ignore_nets: set[subnet] += { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16} &redef;

}

event bro_init() &priority=5
{
  Log::create_stream(X509EXTENDED::LOG, [$columns=Info]);
}

function log_data(f: Files::Info, cert: X509::Certificate, resp_h: addr, resp_p: port): Info
{
  local info: Info;
  info$ts = f$ts;
  info$resp_h = resp_h;
  info$resp_p = resp_p;

  info$cert = cert;

  if (f?$md5) {
    info$md5 = f$md5;
  }

  if (f?$sha1) {
    info$sha1 = f$sha1;
  }

  if (f?$sha256) {
    info$sha256 = f$sha256;
  }

  return info;

}

event file_state_remove(f: fa_file) &priority=5
{
	if ( ! f$info?$x509 ) return;
	if ( ! f?$conns ) return;

  	for (cn in f$conns){
    		if (cn$resp_h !in ignore_nets) {
        		local info = log_data(f$info, f$info$x509$certificate, cn$resp_h, cn$resp_p);
			if (f$info$x509?$san) {
				  info$san = f$info$x509$san;
			}
			Log::write(X509EXTENDED::LOG, info);
    		}
  	}

}
