module MIMEHTMLENTITY;

export {
  const smtp_int_dest: set[subnet] += { 10.0.0.0/8} &redef;
  const max_entity_size = 1000000;

  const ctype_h : pattern += /CONTENT-TYPE/ &redef;
  const ctype_v : pattern += /text\/html/ &redef;
}

global mime_html_entity: event(c: connection, length: count, data: string);

type mime_body: record {
  data: string;
  size: count;
};

global entity_queue: table[string] of mime_body;

function notify_and_remove_from_queue(c: connection){
  local info = entity_queue[c$uid];
  event mime_html_entity(c, info$size, info$data);
  delete entity_queue[c$uid];
}

event mime_one_header(c: connection, h: mime_header_rec){
  if (c$id$resp_h !in smtp_int_dest) return;

  local info: mime_body;
  info$data = "";
  info$size = 0;

  local h_name = h$name;
  local h_val = h$value;
  if ( ctype_h in h_name ) {
    if ( ctype_v in h_val ) {
      entity_queue[c$uid] = info;
    }
  }
}

event mime_segment_data(c: connection, length: count, data: string){
  if ( [c$uid] !in entity_queue ) return;

  local info = entity_queue[c$uid];
  info$data += data;
  info$size += length;

  if ( info$size < max_entity_size ) return;
  notify_and_remove_from_queue(c);
}

event mime_end_entity(c: connection){
  if ( [c$uid] !in entity_queue ) return;
  notify_and_remove_from_queue(c);
}
