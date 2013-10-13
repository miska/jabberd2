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

//! Name of the table where messages are stored
#define tbl_name "archive"
//! How long is the random part of message ID
#define mid_rand_len 4

/** @file sm/mod_archive.c
  * @brief Message archiving module
  * @author Michal Hrusecky
  * $Date: 2006/09/06 01:06:48 $
  * $Revision: 1.4 $
  *
  * Ultimate goal of this module is implementation of XEP-0313, so far only
  * archiving is supported, no queries and no preferences.
  *
  */

typedef enum {
    IN_D  = 1,
    OUT_D = 2,
} direction;

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
    time_t t=0;
    jid_t own_jid, other_jid;
    os_t os;
    os_object_t o;

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
    // Prepare to store them
    os = os_new();
    o = os_object_new(os);

    // What direction are we talking about?
    if (direct == IN_D) {
        own_jid   = pkt->to;
        other_jid = pkt->from;
    } else {
        own_jid   = pkt->from;
        other_jid = pkt->to;
    }

    // Real storing
    log_debug(ZONE, "Saving...");

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

// Module initialization
DLLEXPORT int module_init(mod_instance_t mi, char *arg) {
    log_debug(ZONE, "Archiving plugin init");

    module_t mod = mi->mod;

    if(mod->init) return 0;

    mod->in_router = save_rt_in;
    mod->out_router = save_rt_out;

    feature_register(mod->mm->sm, "urn:xmpp:mam:tmp");

    return 0;
}
