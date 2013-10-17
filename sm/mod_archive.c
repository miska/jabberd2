/*
 * jabberd - Jabber Open Source Server
 * Copyright (c) 2002 Jeremie Miller, Thomas Muldowney,
 *                    Ryan Eatmon, Robert Norris
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA02111-1307USA
 */

#include "sm/sm.h"
#include "util/jid.h"
#include "storage/storage.h"

#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <time.h>

#define max(a,b) (((a)>(b))?(a):(b))
#define min(a,b) (((a)<(b))?(a):(b))

//! Name of the table where messages are stored
#define tbl_name "archive"
//! How long is the random part of message ID
#define mid_rand_len 4
//! URI of the message
#define archive_uri "urn:xmpp:mam:tmp"

/** @file sm/mod_archive.c
  * @brief Message archiving module
  * @author Michal Hrusecky
  *
  * Ultimate goal of this module is implementation of XEP-0313, so far only
  * archiving and setting preferences is supported, no queries yet.
  *
  */

typedef enum {
    IN_D  = 1,
    OUT_D = 2,
} direction;

typedef enum {
    A_NEVER  = 0,
    A_ALWAYS = 1,
    A_ROSTER = 2,
} archiving;

//! Default mode
#define default_mode A_NEVER

static int ns_ARCHIVE = 0;

/**
 * Creates unique ID for every message.
 */
void set_mid(storage_t* st, os_object_t* o, nad_t nad, int arch) {
    static char id[48];
    static char* pos=id+47;
    static char* rand=NULL;
    static pthread_mutex_t mutex;
    time_t tme;
    long int rand_num;
    int i;

    // Lock everything to make sure we have unique IDs
    pthread_mutex_lock(&mutex);
    log_debug(ZONE, "Setting mid...");

    // We had too many messages since boot
    if(pos-id<2)
        pos=id+47;

    // First run of the function
    if(pos-id==47) {
        (*pos)=0;
        pos--;
        // Use current time as a start
        for(tme=time(NULL); ((tme>0) && (pos>id+14)); tme=tme/26) {
            (*pos)='a'+(tme%26);
            pos--;
        }
        (*pos)='-';
        rand=pos-(mid_rand_len);
        pos=rand-1;
        (*pos)='-';
        pos--;
        (*pos)='a';
    }

    // Make message ids unpredictable
    rand_num=random();
    for(i=0; i<mid_rand_len; i++) {
        (*(rand+i)) = 'a' + (rand_num%26);
        rand_num = rand_num / 26;
    }

    // Increment IDs and let it overflow
    if((*pos)=='z') {
        (*(--pos))='a';
    } else {
        (*pos)++;
    }

    // Store ID
    os_object_put(*o, "mid", pos, os_type_STRING);
    // Optionally put it into message
    if(arch > 0)
        nad_set_attr(nad,arch,-1,"id",pos, strlen(pos));

    log_debug(ZONE, "mid set to %s.",pos);
    // Unlock
    pthread_mutex_unlock(&mutex);
}

/**
 * Saves packet into database.
 * @param direct Direction of the message - 2 = incomming, 1 = sent
 */
mod_ret_t savepkt(pkt_t pkt, int direct) {
    int body=-1, sub=-1, type=-1, arch=-1;
    char *mem=NULL;
    const *owner = NULL, *other = NULL;
    int sz = 0;
    int archive=default_mode;
    char filter[2060]; // 2048 is jid_user maximum length
    time_t t=0;
    jid_t own_jid, other_jid;
    os_t os, set_os=NULL;
    os_object_t o, set_o=NULL;

    // Is it a message?
    log_debug(ZONE, "Testing message...");
    if ( (pkt->type & pkt_MESSAGE) == 0)
        return mod_PASS;

    log_debug(ZONE, "It is a message...");

    // 0 element is route, 1st is message, we need subelement of message
    body = nad_find_elem(pkt->nad, 1, -1, "body",    1);
    log_debug(ZONE, "Body is at %d", body);
    sub  = nad_find_elem(pkt->nad, 1, -1, "subject", 1);
    log_debug(ZONE, "Subject is at %d", sub);
    type = nad_find_attr(pkt->nad, 1, -1, "type", NULL);
    log_debug(ZONE, "Type %d", type);

    // Are these parts really interesting?
    if( ( (body < 0) || (NAD_CDATA_L(pkt->nad, body) < 1) ) &&
        ( (sub  < 0) || (NAD_CDATA_L(pkt->nad, sub ) < 1) ) )
        return mod_PASS;

    log_debug(ZONE, "It's meaningful message!", pkt->from);

    // What direction are we talking about?
    if (direct == IN_D) {
        own_jid   = pkt->to;
        other_jid = pkt->from;
    } else {
        own_jid   = pkt->from;
        other_jid = pkt->to;
    }

    // Get JIDs
    if(own_jid != NULL) {
        owner=jid_user(own_jid);
    } else {
        return mod_PASS;
    }
    if(other_jid != NULL) {
        other=jid_user(other_jid);
    } else {
        return mod_PASS;
    }

    // Check settings

    // Load defaults
    snprintf(filter, 2060, "(jid=%s)", owner);
    if((storage_get(pkt->sm->st, tbl_name "_settings", owner, filter, &set_os) == st_SUCCESS) &&
        (os_iter_first(set_os)) && ((set_o=os_iter_object(set_os))!=NULL))
        os_object_get_int(set_os, set_o, "setting", &archive);

    // Cleanup
    if(set_o != NULL) {
        os_object_free(set_o);
        set_o=NULL;
    }
    if(set_os != NULL) {
        os_free(set_os);
        set_os=NULL;
    }

    // Load contact specific
    snprintf(filter, 2060, "(jid=%s)", other);
    if((storage_get(pkt->sm->st, tbl_name "_settings", owner, filter, &set_os) == st_SUCCESS) &&
        (os_iter_first(set_os)) && ((set_o=os_iter_object(set_os))!=NULL))
        os_object_get_int(set_os, set_o, "setting", &archive);

    // Cleanup
    if(set_o != NULL) {
        os_object_free(set_o);
        set_o=NULL;
    }
    if(set_os != NULL) {
        os_free(set_os);
        set_os=NULL;
    }

    // Do we need to check roster?
    if(archive==A_ROSTER) {
        snprintf(filter, 2060, "(jid=%s)", other);
        if(storage_get(pkt->sm->st, "roster-items", owner, filter, &set_os) == st_SUCCESS)
            archive=A_ALWAYS;
        else
            archive=A_NEVER;
        if(set_os != NULL) {
            os_free(set_os);
            set_os=NULL;
        }
    }

    // Decide
    if(archive==A_NEVER)
        return mod_PASS;

    // Prepare to store them
    os = os_new();
    if(os == NULL) return mod_PASS;
    o = os_object_new(os);
    if(o  == NULL) return mod_PASS;

    // Real storing
    log_debug(ZONE, "Saving message for %s (other party is %s)", owner, other);

    // Message

    // Buffer allocation
    if(body > 0) {
        sz = NAD_CDATA_L(pkt->nad, body) / 1024;
        log_debug(ZONE, "Body size %d", NAD_CDATA_L(pkt->nad, body));
    }
    if(sub > 0) {
        sz = max(sz, NAD_CDATA_L(pkt->nad, sub)  / 1024);
        log_debug(ZONE, "Subj size %d", NAD_CDATA_L(pkt->nad, sub));
    }
    log_debug(ZONE, "Creating buffer of size %d", sz);
    mem = (char*)malloc(1024 * (sz+1));
    if(mem == NULL) return mod_PASS;
    log_debug(ZONE, "We got past the buffer allocation.");

    // JID
    os_object_put(o, "other_jid", other, os_type_STRING);

    // Body
    mem[0]=0;
    if ( (body > 0) && (NAD_CDATA_L(pkt->nad, body) > 0) ) {
        strncpy(mem, NAD_CDATA(pkt->nad, body), NAD_CDATA_L(pkt->nad, body));
        mem[NAD_CDATA_L(pkt->nad, body)] = 0;
    }
    os_object_put(o, "message", mem,                        os_type_STRING);

    // Subject
    mem[0]=0;
    if ( (sub  > 0) && (NAD_CDATA_L(pkt->nad, sub ) > 0) ) {
        strncpy(mem, NAD_CDATA(pkt->nad, sub),  NAD_CDATA_L(pkt->nad, sub));
        mem[NAD_CDATA_L(pkt->nad, sub)] = 0;
    }
    os_object_put(o, "subject", mem,                        os_type_STRING);

    // Type
    mem[0]=0;
    if ( (type  > 0) && (NAD_AVAL_L(pkt->nad, type ) > 0) ) {
        strncpy(mem, NAD_AVAL(pkt->nad, type), NAD_AVAL_L(pkt->nad, type));
        mem[NAD_AVAL_L(pkt->nad, type)] = 0;
    }
    os_object_put(o, "type",    mem,                        os_type_STRING);

    // To and from resources
    os_object_put(o, "my_resource",    own_jid->resource,   os_type_STRING);
    os_object_put(o, "other_resource", other_jid->resource, os_type_STRING);

    // Time and direction
    t=time(NULL);
    os_object_put(o, "direct",  &direct,                    os_type_INTEGER);
    os_object_put_time(o, "time",   &t);

    // Message ID
    if (direct == IN_D) {
        arch = nad_insert_elem(pkt->nad, 1, -1, "archived", "");
        nad_set_attr(pkt->nad,arch,-1,"by",jid_user(own_jid), strlen(jid_user(own_jid)));
    }
    set_mid(&(pkt->sm->st), &o, pkt->nad, arch);

    // Save itself
    storage_put(pkt->sm->st, tbl_name, owner, os);

    // Cleanup
    os_object_free(o);
    os_free(os);
    free(mem);
    log_debug(ZONE, "Saved.");

    return mod_PASS;
}

// Wrapper function for router in chain
static mod_ret_t save_rt_in(mod_instance_t mi, pkt_t pkt) {
    log_debug(ZONE, "Got router-in");
    return savepkt(pkt,IN_D);
}

// Wrapper function for router out chain
static mod_ret_t save_rt_out(mod_instance_t mi, pkt_t pkt) {
    log_debug(ZONE, "Got router-out");
    return savepkt(pkt,OUT_D);
}

/** Send archiving preferences */
void send_arch_prefs(mod_instance_t mi, sess_t sess, pkt_t pkt) {
    module_t mod = mi->mod;
    int prefs;
    int archive=default_mode;
    int section;
    int check;
    char buff[2060]; // 2048 is jid_user maximum length
    char* ret_str=buff;
    os_t os = NULL;
    os_object_t o = NULL;
    pkt_t reply;

    // Create a new packet
    log_debug(ZONE, "Construction of reply with current settings");
    reply = pkt_create(sess->user->sm, "iq", "result", NULL, NULL);

    // Defaults
    log_debug(ZONE, "Getting defaults");
    prefs = nad_append_elem(reply->nad, nad_add_namespace(reply->nad, archive_uri, NULL), "prefs", 2);

    // Load defaults
    snprintf(buff, 2060, "(jid=%s)", jid_user(sess->jid));
    if((storage_get(sess->user->sm->st, tbl_name "_settings", jid_user(sess->jid), buff, &os) == st_SUCCESS) &&
        (os_iter_first(os)) && ((o=os_iter_object(os))!=NULL))
            os_object_get_int(os, o, "setting", &archive);

    // Set defaults
    switch(archive) {
        case A_ALWAYS:
            nad_set_attr(reply->nad, prefs, -1,"default", "always", 6);
            break;
        case A_ROSTER:
            nad_set_attr(reply->nad, prefs, -1,"default", "roster", 6);
            break;
        default:
            nad_set_attr(reply->nad, prefs, -1,"default", "never", 5);
            break;
    }


    // Cleanup
    if(o != NULL) {
        os_object_free(o);
        o=NULL;
    }
    if(os != NULL) {
        os_free(os);
        os=NULL;
    }

    // Always archiving
    log_debug(ZONE, "Getting what to archive always");
    section = nad_append_elem(reply->nad, -1, "always", 3);
    if(storage_get(sess->user->sm->st, tbl_name "_settings", jid_user(sess->jid), "(setting=1)", &os) == st_SUCCESS)
    if(os_iter_first(os))
        do {
            o = os_iter_object(os);
            if((o != NULL) && (os_object_get_str(os, o, "jid", &ret_str)) && (ret_str != NULL)) {
                nad_append_elem(reply->nad, -1, "jid", 4);
                nad_append_cdata(reply->nad, ret_str, strlen(ret_str), 5);
            }
        } while(os_iter_next(os));

    // Cleanup
    if(o != NULL) {
        os_object_free(o);
        o=NULL;
    }
    if(os != NULL) {
        os_free(os);
        os=NULL;
    }

    // Never archiving
    log_debug(ZONE, "Getting what to never archive");
    section = nad_append_elem(reply->nad, -1, "never", 3);
    if(storage_get(sess->user->sm->st, tbl_name "_settings", jid_user(sess->jid), "(setting=0)", &os) == st_SUCCESS)
    if(os_iter_first(os))
        do {
            o = os_iter_object(os);
            if((o != NULL) && (os_object_get_str(os, o, "jid", &ret_str)) && (ret_str != NULL)) {
                nad_append_elem(reply->nad, -1, "jid", 4);
                nad_append_cdata(reply->nad, ret_str, strlen(ret_str), 5);
            }
        } while(os_iter_next(os));

    // Cleanup
    if(o != NULL) {
        os_object_free(o);
        o=NULL;
    }
    if(os != NULL) {
        os_free(os);
        os=NULL;
    }

    // Send packet
    pkt_id(pkt, reply);
    pkt_sess(reply, sess);
    pkt_free(pkt);
}

/** Handles iq messages */
mod_ret_t archive_iq_in_sess(mod_instance_t mi, sess_t sess, pkt_t pkt) {
    int prefs, type;
    int section, ptr;
    os_t os;
    os_object_t o;
    char* owner;
    char buff[2048];
    log_debug(ZONE, "In session");

    // we only want to play IQs
    if((!((pkt->type & pkt_IQ) || (pkt->type & pkt_IQ_SET))) || (pkt->ns != ns_ARCHIVE))
        return mod_PASS;
    log_debug(ZONE, "Passed through packet checks");

    // if it has a to, throw it out
    if(pkt->to != NULL)
        return -stanza_err_BAD_REQUEST;

    // Who are we?
    owner=jid_user(sess->jid);

    // Check for no type or get to send current settings
    if((type = (nad_find_attr(pkt->nad, 2, -1, "type", NULL)<0)) ||
       ((NAD_AVAL_L(pkt->nad, type ) == 3) && strncmp("get", NAD_AVAL(pkt->nad, type), 3))) {
        log_debug(ZONE, "Somebody is asking about settings");
        send_arch_prefs(mi, sess, pkt);
        return mod_HANDLED;
    }

    // We are setting stuff
    if(pkt->type == pkt_IQ_SET) {
        // Prepare to store them
        log_debug(ZONE, "Setting archiving preferences...");
        os = os_new();
        if(os == NULL) return mod_PASS;
        o = os_object_new(os);
        if(o  == NULL) return mod_PASS;

        // Get rid of old settings
        storage_delete(pkt->sm->st, tbl_name "_settings", owner, NULL);
        log_debug(ZONE, "Got rid of old preferences...");

        // Find if there is an default option
        if(!((prefs=nad_find_elem(pkt->nad, 1, -1, "prefs", 1))>0))
            return mod_PASS;
        ptr=nad_find_attr(pkt->nad, prefs, -1, "default", NULL);

        if(ptr>0) {
            // Defaults
            log_debug(ZONE, "Saving defaults...");
            os_object_put(o, "jid", owner, os_type_STRING);
            if     (strncmp("roster",NAD_AVAL(pkt->nad, ptr), NAD_AVAL_L(pkt->nad, ptr))==0)
                prefs=A_ROSTER;
            else if(strncmp("always",NAD_AVAL(pkt->nad, ptr), NAD_AVAL_L(pkt->nad, ptr))==0)
                prefs=A_ALWAYS;
            else
                prefs=A_NEVER;
            os_object_put(o, "setting", &prefs,  os_type_INTEGER);
            log_debug(ZONE, "Setting default to %d...", prefs);

            // What to save always
            log_debug(ZONE, "Saving what to save always...");
            if(((section = nad_find_elem(pkt->nad, prefs, -1, "always", 1))>0)) {
                log_debug(ZONE, "Found always section %d...", section);
                prefs=A_ALWAYS;
                for(ptr = nad_find_elem(pkt->nad, section, -1, "jid", 1); ptr > 0;
                    ptr = nad_find_elem(pkt->nad, ptr,     -1, "jid", 0)) {
                        o = os_object_new(os);
                        strncpy(buff, NAD_CDATA(pkt->nad, ptr), min(2047,NAD_CDATA_L(pkt->nad, ptr)));
                        buff[min(2047,NAD_CDATA_L(pkt->nad, ptr))]=0;
                        os_object_put(o, "jid",      buff,  os_type_STRING);
                        os_object_put(o, "setting", &prefs, os_type_INTEGER);
                        log_debug(ZONE, "Always archiving %s...", buff);
                }
            }

            // What to never save
            log_debug(ZONE, "Saving what never save...");
            if(((section = nad_find_elem(pkt->nad, 2, -1, "never",  1))>0)) {
                log_debug(ZONE, "Found never section %d...", section);
                prefs=A_NEVER;
                for(ptr = nad_find_elem(pkt->nad, section, -1, "jid", 1); ptr > 0;
                    ptr = nad_find_elem(pkt->nad, ptr,     -1, "jid", 0)) {
                        o = os_object_new(os);
                        strncpy(buff, NAD_CDATA(pkt->nad, ptr), min(2047,NAD_CDATA_L(pkt->nad, ptr)));
                        buff[min(2047,NAD_CDATA_L(pkt->nad, ptr))]=0;
                        os_object_put(o, "jid",      buff,  os_type_STRING);
                        os_object_put(o, "setting", &prefs, os_type_INTEGER);
                        log_debug(ZONE, "Never archiving %s...", buff);
                }
            }

            // Save everything
            storage_put(pkt->sm->st, tbl_name "_settings", owner, os);
        }

        // Send current settings
        send_arch_prefs(mi, sess, pkt);
        return mod_HANDLED;
    }
    return mod_PASS;
}


// Module initialization
DLLEXPORT int module_init(mod_instance_t mi, char *arg) {
    log_debug(ZONE, "Archiving plugin init");

    module_t mod = mi->mod;

    if(mod->init) return 0;

    mod->in_router = save_rt_in;
    mod->in_sess = archive_iq_in_sess;
    mod->out_router = save_rt_out;

    feature_register(mod->mm->sm, archive_uri);
    ns_ARCHIVE = sm_register_ns(mod->mm->sm, archive_uri);

    return 0;
}
