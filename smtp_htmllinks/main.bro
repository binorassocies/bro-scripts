@load ./mime_html_entity
@load base/utils/urls

module SMTPEXTENDEDURL;

redef MIMEHTMLENTITY::smtp_int_dest = { 10.10.10.0/24};

export {
  redef enum Log::ID += { LOG };

  type Info: record {
    urldomains: set[string] &log &optional;
  };
  global log_smtpextendedurl: event(rec: SMTP::Info);

  const html_links_regex : pattern += /(<a[[:blank:]\r\n]+[^>]+>)(\n|\r|[^<])+(<\/a>)/;
}

redef record SMTP::Info += {
  smtp_e: SMTPEXTENDEDURL::Info &log &optional;
};

event bro_init() &priority=5
{
  Log::create_stream(SMTPEXTENDEDURL::LOG, [$columns=SMTP::Info, $ev=log_smtpextendedurl, $path="smtpextendedurl"]);
}

function find_all_links(s: string): string_set
{
  return find_all(s, html_links_regex);
}

function extract_link_domain(s: string): string
{
  local r = "";
  local t_var_1 = split_string1(s, />/);
  if (|t_var_1| == 2) {
    local t_var_2 = split_string(t_var_1[0], /([[:blank:]\r\n])/);
    for (i in t_var_2) {
      if (/^href=/ in t_var_2[i]){
        local att = sub(t_var_2[i], /=3D/, "=");
        att = sub(att, /href=/, "");
        att = gsub(att, /\"/, "");
        att = strip(att);
        if (/^(https?|ftp):\/\// in att) {
          local durl = decompose_uri(att);
          local att_d = durl$netlocation;
          r = to_lower(att_d);
        }
        break;
      }
    }
  }
  return r;
}

event mime_html_entity(c: connection, length: count, data: string)
{
  if ( ! c?$smtp ) return;
  if ( c$smtp?$tls && c$smtp$tls ) return;

  local seen_domains : set[string];
  local html_links = find_all_links(data);

  for (link in html_links) {
    local url_dom = extract_link_domain(link);
    if ( url_dom != "" &&  url_dom !in seen_domains ) {
      add seen_domains[url_dom];
    }
  }

  if (|seen_domains| > 0 ) {
    local info: Info;
    info$urldomains = seen_domains;
    c$smtp$smtp_e = info;
    Log::write(LOG, c$smtp);
  }

}
