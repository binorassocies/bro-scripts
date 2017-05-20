@load ./mime_html_entity
@load ./whitelist_domains
@load base/utils/urls

redef MIMEHTMLENTITY::smtp_int_dest = { 10.220.2.0/24, 10.217.3.0/24, 172.30.76.10/24};

const html_links_regex : pattern += /(<a[[:blank:]\r\n]+[^>]+>[^<]+(<\/a>))/;

module SMTPHTMLLINKS;

export {
  redef enum Log::ID += { LOG };

  type Info: record {
    ## When the email was seen.
    ts:   time    &log;
    ## Unique ID for the connection.
    uid:  string  &log;
    ## Connection details.
    id:   conn_id &log;
    ## email sender
    mailfrom: string &log &optional;
    ## from domain.
    from: string &log &optional;
    ## url domain
    urldomain:  string  &log &optional;
    ## is mismatching domain in link text
    alertmsg:  string  &log &optional;
    ## domain found in the text domain
    textdomain:  string  &log &optional;
    ## url displayed when there is an alert
    url:  string  &log &optional;
  };
}

type html_link: record {
  href: string;
  hrefdomain: string;
  textisdomain: bool;
  text: string;
  textdomain: string;
};

event bro_init() &priority=5
{
  Log::create_stream(SMTPHTMLLINKS::LOG, [$columns=Info]);
}

function find_all_links(s: string): string_set
{
  return find_all(s, html_links_regex);
}

function log_smtp_url(c: connection, mailfrom:string, from: string, urldomain: string, alertmsg: string, textdomain: string, url: string)
{
  local info: Info;
  info$ts = c$smtp$ts;
  info$uid = c$smtp$uid;
  info$id = c$id;
  info$mailfrom = mailfrom;
  info$from = from;

  info$urldomain = urldomain;
  if (alertmsg != "N") {
    info$alertmsg = alertmsg;
    info$url = url;
    if (textdomain != ""){
      info$textdomain = textdomain;
    }
  }
  Log::write(SMTPHTMLLINKS::LOG, info);
}

function extract_url_domain(s: string): string
{
  local res = "";
  s = strip(s);
  if (/^(https?|ftp):\/\// in s) {
    local durl = decompose_uri(s);
    local att_d = durl$netlocation;
    res = to_lower(att_d);
  }
  return res;
}

function extract_link_record(s: string): html_link
{
  local r: html_link = [$href = "", $text = "", $hrefdomain = "", $textisdomain = F, $textdomain = ""];

  local t_var_1 = split_string1(s, />/);
  if (|t_var_1| == 2) {
    local t_var_2 = split_string(t_var_1[0], /([[:blank:]\r\n])/);
    for (i in t_var_2){
      if (/^href=/ in t_var_2[i]){
        local att = sub(t_var_2[i], /href=/, "");
        att = gsub(att, /\"/, "");
        r$href = att;
        r$hrefdomain = extract_url_domain(att);
        break;
      }
    }

    t_var_2 = split_string1(t_var_1[1], /</);
    if (|t_var_2| == 2) {
      local lkn = strip(t_var_2[0]);
      r$text = lkn;
      if (/([A-Za-z0-9-]{1,63}\.)+([A-Za-z]{2,})/ == lkn) {
        r$textdomain = lkn;
        r$textisdomain = T;
      }
    }
  }
  return r;
}

function compare_domains(ds: string, dt: string): bool
{
  local res = T;
  local ds_r = reverse(ds);
  local dt_r = reverse(dt);
  local ds_l = split_string(ds_r, /\./);
  local dt_l = split_string(dt_r, /\./);
  local ll = min_count(|ds_l|, |dt_l|);
  local llc = min_count(3, ll);

  local i = 0;
  while ( i < llc ) {
    if (ds_l[i] != dt_l[i]) {
      res = F;
      break;
    }
    ++i;
  }
  return res;
}

function analyse_url(url: html_link): string
{
  local res = "N";
  if (url$textisdomain){
    local r = compare_domains(url$hrefdomain, url$textdomain);
    if (!r) {
      res = "Alert: Link target and displayed domain name do not match!";
    }
  }
  return res;
}

event mime_html_entity(c: connection, length: count, data: string)
{
  local mailfrom = "";
  local from = "";

  if (c$smtp?$mailfrom) {
    mailfrom = c$smtp$mailfrom;
  }

  if (c$smtp?$from) {
    from = c$smtp$from;
  }

  local seen_domains : set[string];
  local html_links = find_all_links(data) ;

  for (link in html_links){
    local url_link = extract_link_record(link);
    if ( url_link$hrefdomain != "" &&  url_link$hrefdomain !in seen_domains && ignore_sites !in url_link$hrefdomain ) {
      local msg = analyse_url(url_link);
      add seen_domains[url_link$hrefdomain];
      log_smtp_url(c, mailfrom, from, url_link$hrefdomain, msg, url_link$textdomain, url_link$href);
    }
  }
}
