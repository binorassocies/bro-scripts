module X509EXTENDED;

export {
  redef enum Log::ID += { LOG };

  type Info: record {
    resp_h: addr &log;
    resp_p: port &log;
  };
  global log_x509extended: event(rec: X509::Info);
}

redef record X509::Info += {
  x509_e: X509EXTENDED::Info &log &optional;
};

event bro_init() &priority=5
{
  Log::create_stream(X509EXTENDED::LOG, [$columns=X509::Info, $ev=log_x509extended, $path="x509extended"]);
}

event file_state_remove(f: fa_file) &priority=5
{
  if ( ! f$info?$x509 ) return;
  if ( ! f?$conns ) {
    Log::write(LOG, f$info$x509);
  } else {
    for (cn in f$conns) {
      local info: Info;
      info$resp_h = cn$resp_h;
      info$resp_p = cn$resp_p;
      f$info$x509$x509_e = info;

      Log::write(LOG, f$info$x509);

    }
  }

}
