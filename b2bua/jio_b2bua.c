/* jio_b2bua.c — JioFiber (JUICE) <-> Asterisk back-to-back UA.
 *
 * Leg A (acc_jio):   registers to the JioFiber router's JUICE server over TLS,
 *                    advertising IMS voice/RCS capability so incoming calls are
 *                    forked to us. Media: AMR (as JUICE requires) <-> PCMU.
 * Leg B (acc_trunk): static UDP trunk to an Asterisk instance (over your overlay
 *                    network, e.g. Tailscale/WireGuard). Media: PCMU.
 *
 * Bridges calls both directions; pjsua's conf bridge transcodes AMR<->PCMU.
 * DTMF (RFC2833) is relayed explicitly (the conf bridge doesn't carry it).
 * Proper B2BUA signaling: mirrors 180/183/200 and propagates failure codes.
 *
 * Identity comes from environment variables (fill these in, see bridge.env):
 *   SIP_PUBLIC_ID   e.g. sip:+<CC><NUMBER>@<REALM>     (WITH the +)
 *   SIP_REALM       e.g. <circle>.wln.ims.jio.com
 *   REGISTRAR       e.g. sip:jiofiber.local.html:5068;transport=tls  (the router)
 * Runtime values come from argv:
 *   argv: jio_b2bua <auth_user> <password> <bridge_overlay_ip> <asterisk_overlay_ip> <bridge_lan_ip>
 *     auth_user            = SIP digest authid, e.g. <CC><NUMBER>@<REALM>  (NO +)
 *     password             = the *rotating* userpwd (fetch fresh at each start)
 *     bridge_overlay_ip    = this host's overlay (Tailscale) IP  -> trunk + trunk RTP
 *     asterisk_overlay_ip  = Asterisk's overlay IP               -> where inbound calls go
 *     bridge_lan_ip        = this host's LAN IP on the router subnet -> JUICE-leg RTP
 */
#include <pjsua-lib/pjsua.h>
#include <stdlib.h>
#include <string.h>
#define THIS_FILE "JIOB2BUA"
#define TRUNK_PORT      5070   /* local SIP port for the Asterisk trunk */
#define ASTERISK_PORT   5560   /* Asterisk's SIP port for the trunk     */

static pjsua_acc_id g_acc_jio = PJSUA_INVALID_ID;
static pjsua_acc_id g_acc_trunk = PJSUA_INVALID_ID;
static char g_asterisk[64];                   /* Asterisk overlay IP */
static char g_realm[128];                     /* SIP realm for outbound R-URI */
static pjsua_call_id g_peer[PJSUA_MAX_CALLS]; /* call_id -> bridged peer call_id */
static pj_bool_t g_bleg[PJSUA_MAX_CALLS];     /* TRUE if this call is the outgoing (B) leg */
static int g_prov[PJSUA_MAX_CALLS];           /* last provisional code relayed to this (A) leg */

static void err(const char*t, pj_status_t s){ pjsua_perror(THIS_FILE,t,s); pjsua_destroy(); exit(1); }
static void on_reg_state(pjsua_acc_id acc){ pjsua_acc_info i; pjsua_acc_get_info(acc,&i);
    PJ_LOG(3,(THIS_FILE,">>> acc=%d REG status=%d %.*s",acc,i.status,(int)i.status_text.slen,i.status_text.ptr)); }

/* Per-leg RTP dump (codec, peer addr, tx/rx pkt counts, loss) — invaluable for one-way-audio debugging */
static void dump_call(pjsua_call_id id, const char* when){
    char buf[3072];
    if (pjsua_call_is_active(id) && pjsua_call_dump(id, PJ_TRUE, buf, sizeof(buf), "  ")==PJ_SUCCESS)
        PJ_LOG(3,(THIS_FILE,"=== [%s] call %d ===\n%s", when, id, buf));
}

static void on_incoming_call(pjsua_acc_id acc_id, pjsua_call_id call_id, pjsip_rx_data *rdata){
    pjsua_call_info ci; PJ_UNUSED_ARG(rdata);
    pjsua_call_get_info(call_id,&ci);
    PJ_LOG(3,(THIS_FILE,"Incoming call %d on acc %d from %.*s to %.*s",call_id,acc_id,
        (int)ci.remote_info.slen,ci.remote_info.ptr,(int)ci.local_info.slen,ci.local_info.ptr));
    char dsturi[256]; pjsua_call_setting cs; pjsua_call_setting_default(&cs);
    pjsua_call_id peer = PJSUA_INVALID_ID; pj_str_t d;
    if (acc_id == g_acc_jio) {
        /* INBOUND landline call -> ring Asterisk (which forks to your phones). Pass caller-id. */
        char ri[256]; int ril=(int)(ci.remote_info.slen<255?ci.remote_info.slen:255);
        memcpy(ri,ci.remote_info.ptr,ril); ri[ril]=0;
        char caller[64]=""; char*cp=strstr(ri,"sip:");
        if(cp){ cp+=4; char*ca=strchr(cp,'@'); int ck=ca?(int)(ca-cp):0; if(ck>0&&ck<63){ memcpy(caller,cp,ck); caller[ck]=0; } }
        pj_ansi_snprintf(dsturi,sizeof(dsturi),"sip:s@%s:%d",g_asterisk,ASTERISK_PORT);
        d=pj_str(dsturi);
        pjsua_msg_data md; pjsua_msg_data_init(&md);
        pjsip_generic_string_hdr hdr; pj_str_t hn=pj_str("X-Jio-Caller"), hv=pj_str(caller);
        pjsip_generic_string_hdr_init2(&hdr,&hn,&hv); pj_list_push_back(&md.hdr_list,&hdr);
        PJ_LOG(3,(THIS_FILE,"inbound caller=%s",caller));
        if (pjsua_call_make_call(g_acc_trunk,&d,&cs,NULL,(caller[0]?&md:NULL),&peer)!=PJ_SUCCESS) { pjsua_call_hangup(call_id,503,NULL,NULL); return; }
    } else if (acc_id == g_acc_trunk) {
        /* OUTBOUND: a phone dialed a number. Extract the user part of the To/request URI. */
        char li[256]; int lil=(int)(ci.local_info.slen<255?ci.local_info.slen:255);
        memcpy(li,ci.local_info.ptr,lil); li[lil]=0;
        char num[64]=""; char *p=strstr(li,"sip:");
        if(p){ p+=4; char*at=strchr(p,'@'); int k=at?(int)(at-p):0; if(k>0&&k<63){ memcpy(num,p,k); num[k]=0; } }
        if(!num[0]){ PJ_LOG(3,(THIS_FILE,"no number in %s",li)); pjsua_call_hangup(call_id,404,NULL,NULL); return; }
        PJ_LOG(3,(THIS_FILE,"outbound dial number=%s",num));
        pj_ansi_snprintf(dsturi,sizeof(dsturi),"sip:%s@%s",num,g_realm);  /* routed via the router proxy */
        d=pj_str(dsturi);
        if (pjsua_call_make_call(g_acc_jio,&d,&cs,NULL,NULL,&peer)!=PJ_SUCCESS){ pjsua_call_hangup(call_id,503,NULL,NULL); return; }
    } else { pjsua_call_hangup(call_id,488,NULL,NULL); return; }
    g_peer[call_id]=peer; g_prov[call_id]=0;
    if(peer>=0&&peer<PJSUA_MAX_CALLS){ g_peer[peer]=call_id; g_bleg[peer]=PJ_TRUE; }
    /* Do NOT answer the A-leg here; it is answered only when the B-leg (peer) progresses. */
}
static void on_call_media_state(pjsua_call_id call_id){
    pjsua_call_info ci; pjsua_call_get_info(call_id,&ci);
    if (ci.media_status==PJSUA_CALL_MEDIA_ACTIVE){
        pjsua_call_id peer=g_peer[call_id];
        if (peer>=0 && peer<PJSUA_MAX_CALLS){
            pjsua_call_info pj; if(pjsua_call_get_info(peer,&pj)==PJ_SUCCESS && pj.media_status==PJSUA_CALL_MEDIA_ACTIVE){
                pjsua_conf_connect(ci.conf_slot,pj.conf_slot);   /* bidirectional -> AMR<->PCMU transcode */
                pjsua_conf_connect(pj.conf_slot,ci.conf_slot);
                PJ_LOG(3,(THIS_FILE,"bridged media %d <-> %d",call_id,peer));
                dump_call(call_id,"media-active"); dump_call(peer,"media-active-peer");
            }
        }
    }
}
static void on_call_state(pjsua_call_id call_id, pjsip_event *e){
    pjsua_call_info ci; PJ_UNUSED_ARG(e); pjsua_call_get_info(call_id,&ci);
    PJ_LOG(3,(THIS_FILE,"call %d state=%.*s (last=%d)",call_id,(int)ci.state_text.slen,ci.state_text.ptr,ci.last_status));
    pjsua_call_id peer=g_peer[call_id];
    /* Outgoing (B) leg: mirror its signaling to the incoming (A) leg (proper B2BUA behavior) */
    if (g_bleg[call_id] && peer>=0 && peer<PJSUA_MAX_CALLS && pjsua_call_is_active(peer)){
        if (ci.state==PJSIP_INV_STATE_EARLY){
            int code=ci.last_status;
            if (code>=180 && code<200 && g_prov[peer]!=code){
                g_prov[peer]=code;
                pjsua_call_answer(peer, code, NULL, NULL); /* relay 180/183 (183 -> early media) */
            }
        } else if (ci.state==PJSIP_INV_STATE_CONFIRMED){
            pjsua_call_answer(peer, 200, NULL, NULL);       /* far end answered -> answer caller */
        }
    }
    if (ci.state==PJSIP_INV_STATE_DISCONNECTED){
        dump_call(call_id,"disconnect");
        int failcode = (g_bleg[call_id] && ci.last_status>=300 && ci.last_status<700)? ci.last_status : 0;
        g_peer[call_id]=PJSUA_INVALID_ID; g_bleg[call_id]=PJ_FALSE; g_prov[call_id]=0;
        if(peer>=0&&peer<PJSUA_MAX_CALLS){
            g_peer[peer]=PJSUA_INVALID_ID; g_bleg[peer]=PJ_FALSE; g_prov[peer]=0;
            if(pjsua_call_is_active(peer)) pjsua_call_hangup(peer, failcode, NULL, NULL); /* propagate reject */
        }
    }
}
static void set_codecs(void){
    /* PCMU + AMR-WB + AMR-NB; trim the rest to keep SDP small (matters for MTU over the tunnel) */
    const pj_str_t keep_pcmu=pj_str("PCMU/8000/1");
    const pj_str_t keep_amrwb=pj_str("AMR-WB/16000/1");
    const pj_str_t keep_amr=pj_str("AMR/8000/1");
    pjsua_codec_info c[64]; unsigned n=PJ_ARRAY_SIZE(c);
    if (pjsua_enum_codecs(c,&n)!=PJ_SUCCESS) return;
    for(unsigned i=0;i<n;i++){
        if(!pj_stricmp(&c[i].codec_id,&keep_pcmu)) pjsua_codec_set_priority(&c[i].codec_id,254);
        else if(!pj_stricmp(&c[i].codec_id,&keep_amrwb)) pjsua_codec_set_priority(&c[i].codec_id,252);
        else if(!pj_stricmp(&c[i].codec_id,&keep_amr)) pjsua_codec_set_priority(&c[i].codec_id,250);
        else pjsua_codec_set_priority(&c[i].codec_id,0);
    }
}
/* RFC2833 DTMF isn't carried by the conf bridge — relay each digit to the peer leg explicitly */
static void on_dtmf_digit(pjsua_call_id call_id, int digit){
    pjsua_call_id peer=g_peer[call_id];
    if(peer>=0 && peer<PJSUA_MAX_CALLS && pjsua_call_is_active(peer)){
        char ds[2]; ds[0]=(char)digit; ds[1]=0; pj_str_t d=pj_str(ds);
        pjsua_call_dial_dtmf(peer,&d);
        PJ_LOG(3,(THIS_FILE,"DTMF '%c' relayed %d->%d",(char)digit,call_id,peer));
    }
}

int main(int argc,char*argv[]){
    pj_status_t st; for(int i=0;i<PJSUA_MAX_CALLS;i++) g_peer[i]=PJSUA_INVALID_ID;
    if(argc<6){ printf("usage: %s <auth_user> <password> <bridge_overlay_ip> <asterisk_overlay_ip> <bridge_lan_ip>\n",argv[0]); return 1; }
    const char*user=argv[1],*pass=argv[2],*bridge_ts=argv[3]; strncpy(g_asterisk,argv[4],sizeof(g_asterisk)-1);
    const char*lan_ip=argv[5];
    const char *pub_id = getenv("SIP_PUBLIC_ID");   /* sip:+<CC><NUMBER>@<REALM> */
    const char *realm  = getenv("SIP_REALM");       /* <circle>.wln.ims.jio.com  */
    const char *registrar = getenv("REGISTRAR");    /* sip:jiofiber.local.html:5068;transport=tls */
    if(!pub_id||!realm){ printf("ERROR: set SIP_PUBLIC_ID and SIP_REALM env vars\n"); return 1; }
    if(!registrar) registrar="sip:jiofiber.local.html:5068;transport=tls";
    strncpy(g_realm,realm,sizeof(g_realm)-1);

    st=pjsua_create(); if(st!=PJ_SUCCESS) err("create",st);
    { pjsua_config cfg; pjsua_logging_config lc; pjsua_config_default(&cfg);
      cfg.user_agent=pj_str("JUICEJFV-1.3.32");  /* JioFiber-recognized UA (required for inbound forking) */
      cfg.cb.on_reg_state=&on_reg_state; cfg.cb.on_incoming_call=&on_incoming_call;
      cfg.cb.on_call_media_state=&on_call_media_state; cfg.cb.on_call_state=&on_call_state; cfg.cb.on_dtmf_digit=&on_dtmf_digit;
      pjsua_logging_config_default(&lc); lc.console_level=4; lc.level=5; lc.log_filename=pj_str("/tmp/b2pj.log");
      st=pjsua_init(&cfg,&lc,NULL); if(st!=PJ_SUCCESS) err("init",st); }
    /* TLS transport for JUICE (self-signed router cert -> verify off) */
    { pjsua_transport_config t; pjsua_transport_config_default(&t); t.port=5062;
      t.tls_setting.verify_server=PJ_FALSE; t.tls_setting.verify_client=PJ_FALSE; t.tls_setting.method=PJSIP_SSL_UNSPECIFIED_METHOD;
      st=pjsua_transport_create(PJSIP_TRANSPORT_TLS,&t,NULL); if(st!=PJ_SUCCESS) err("tls",st); }
    /* UDP transport bound to the overlay IP for the Asterisk trunk */
    pjsua_transport_id tid_udp;
    { pjsua_transport_config t; pjsua_transport_config_default(&t); t.port=TRUNK_PORT; t.bound_addr=pj_str((char*)bridge_ts);
      st=pjsua_transport_create(PJSIP_TRANSPORT_UDP,&t,&tid_udp); if(st!=PJ_SUCCESS) err("udp trunk",st); }
    st=pjsua_start(); if(st!=PJ_SUCCESS) err("start",st);
    pjsua_set_null_snd_dev(); set_codecs();
    /* acc_jio: register to JUICE */
    { pjsua_acc_config c; pjsua_acc_config_default(&c);
      c.id=pj_str((char*)pub_id);
      c.reg_uri=pj_str((char*)registrar);
      c.proxy_cnt=1; c.proxy[0]=pj_str((char*)registrar);   /* route outbound calls via the router */
      c.cred_count=1; c.cred_info[0].realm=pj_str("*"); c.cred_info[0].scheme=pj_str("digest");
      c.cred_info[0].username=pj_str((char*)user); c.cred_info[0].data_type=PJSIP_CRED_DATA_PLAIN_PASSWD;
      c.cred_info[0].data=pj_str((char*)pass); c.use_rfc5626=PJ_TRUE;
      /* Pin JUICE-leg RTP to the LAN interface (the router is on the LAN) */
      pjsua_transport_config_default(&c.rtp_cfg); c.rtp_cfg.port=4000; c.rtp_cfg.bound_addr=pj_str((char*)lan_ip); c.rtp_cfg.public_addr=pj_str((char*)lan_ip);
      /* Advertise IMS MMTEL (voice) + RCS capability so JUICE forks INBOUND voice calls to us.
       * This full set + the JUICEJFV User-Agent is REQUIRED for inbound; mmtel alone is not enough. */
      c.reg_contact_params=pj_str(";+g.3gpp.icsi-ref=\"urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel\";+g.3gpp.iari-ref=\"urn%3Aurn-7%3A3gpp-application.ims.iari.rcs.jio.eucr\";+g.gsma.rcs.telephony=\"none\";video");
      st=pjsua_acc_add(&c,PJ_TRUE,&g_acc_jio); if(st!=PJ_SUCCESS) err("acc_jio",st); }
    /* acc_trunk: static trunk toward Asterisk (no registration) */
    { pjsua_acc_config c; pjsua_acc_config_default(&c);
      char idbuf[128]; pj_ansi_snprintf(idbuf,sizeof(idbuf),"sip:jiobridge@%s:%d",bridge_ts,TRUNK_PORT);
      c.id=pj_str(idbuf); c.reg_uri=pj_str((char*)""); c.transport_id=tid_udp;
      /* Pin trunk-leg RTP to the overlay interface (so Asterisk over the tunnel can route audio back) */
      pjsua_transport_config_default(&c.rtp_cfg); c.rtp_cfg.port=5000; c.rtp_cfg.bound_addr=pj_str((char*)bridge_ts); c.rtp_cfg.public_addr=pj_str((char*)bridge_ts);
      st=pjsua_acc_add(&c,PJ_FALSE,&g_acc_trunk); if(st!=PJ_SUCCESS) err("acc_trunk",st); }
    PJ_LOG(3,(THIS_FILE,"B2BUA up: acc_jio=%d acc_trunk=%d trunk=%s:%d asterisk=%s",g_acc_jio,g_acc_trunk,bridge_ts,TRUNK_PORT,g_asterisk));
    for(;;) pj_thread_sleep(3600000);
}
