#ifndef _I_IROT_KM_H_
#define _I_IROT_KM_H_

void irot_generate_key(DBusConnection *connection, DBusMessage *request);
void irot_import_key(DBusConnection *connection, DBusMessage *request);
void irot_export_key(DBusConnection *connection, DBusMessage *request);
void irot_envelope_begin(DBusConnection *connection, DBusMessage *request);
void irot_envelope_update(DBusConnection *connection, DBusMessage *request);
void irot_envelope_finish(DBusConnection *connection, DBusMessage *request);
void irot_mac(DBusConnection *connection, DBusMessage *request);
void irot_sign(DBusConnection *connection, DBusMessage *request);
void irot_verify(DBusConnection *connection, DBusMessage *request);
void irot_asym_encrypt(DBusConnection *connection, DBusMessage *request);
void irot_asym_decrypt(DBusConnection *connection, DBusMessage *request);
void irot_cipher(DBusConnection *connection, DBusMessage *request);
void irot_delete_key(DBusConnection *connection, DBusMessage *request);
void irot_delete_all(DBusConnection *connection, DBusMessage *request);
void irot_init(DBusConnection *connection, DBusMessage *request);
void irot_cleanup(DBusConnection *connection, DBusMessage *request);
void irot_get_id2(DBusConnection *connection, DBusMessage *request);
void irot_set_id2(DBusConnection *connection, DBusMessage *request);
void irot_get_attestation(DBusConnection *connection, DBusMessage *request);

#endif /* _I_IROT_KM_H_ */
