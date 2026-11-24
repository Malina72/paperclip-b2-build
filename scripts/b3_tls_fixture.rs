// Build-only integration fixture. No Paperclip runtime or provider is invoked.
use std::{fs, io::Cursor, sync::Arc, time::{Duration, SystemTime, UNIX_EPOCH}};
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
fn read(name: &str) -> Vec<u8> { fs::read(format!("{}/{}", std::env::var("B3_CERT_DIR").unwrap(),name)).unwrap() }
#[derive(Debug)] struct FutureTime;
impl rustls::time_provider::TimeProvider for FutureTime {
 fn current_time(&self)->Option<UnixTime> { Some(UnixTime::since_unix_epoch(Duration::from_secs(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()+7*86400))) }
}
fn handshake(trust: bool, name: &str, corrupt: bool, future: bool)->Result<(),String> {
 let provider=Arc::new(rustls::crypto::ring::default_provider());
 let mut roots=RootCertStore::empty();if trust {roots.add(CertificateDer::from(read("root.der"))).unwrap();}
 let mut client=ClientConfig::builder_with_provider(provider.clone()).with_safe_default_protocol_versions().unwrap().with_root_certificates(roots).with_no_client_auth();
 if future {client.time_provider=Arc::new(FutureTime);}
 let mut leaf=read("leaf.der");if corrupt {let n=leaf.len();leaf[n-1]^=1;}
 let server=ServerConfig::builder_with_provider(provider).with_safe_default_protocol_versions().unwrap().with_no_client_auth().with_single_cert(vec![CertificateDer::from(leaf)],PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(read("leaf.key.der")))).unwrap();
 let mut c=ClientConnection::new(Arc::new(client),ServerName::try_from(name.to_owned()).unwrap()).unwrap();let mut s=ServerConnection::new(Arc::new(server)).unwrap();
 for _ in 0..32 {
  let mut b=Vec::new();c.write_tls(&mut b).map_err(|e|format!("{e:?}"))?;
  if !b.is_empty(){s.read_tls(&mut Cursor::new(b)).map_err(|e|format!("{e:?}"))?;s.process_new_packets().map_err(|e|format!("{e:?}"))?;}
  let mut b=Vec::new();s.write_tls(&mut b).map_err(|e|format!("{e:?}"))?;
  if !b.is_empty(){c.read_tls(&mut Cursor::new(b)).map_err(|e|format!("{e:?}"))?;c.process_new_packets().map_err(|e|format!("{e:?}"))?;}
  if !c.is_handshaking() && !s.is_handshaking(){return Ok(());}
 } Err("bounded handshake did not complete".to_owned())
}
#[test] fn trusted_chain(){handshake(true,"fixture.invalid",false,false).unwrap();}
#[test] fn untrusted_chain(){assert!(handshake(false,"fixture.invalid",false,false).unwrap_err().contains("UnknownIssuer"));}
#[test] fn wrong_hostname(){assert!(handshake(true,"wrong.invalid",false,false).unwrap_err().contains("NotValidForName"));}
#[test] fn corrupted_signature(){assert!(handshake(true,"fixture.invalid",true,false).is_err());}
#[test] fn expired_chain(){assert!(handshake(true,"fixture.invalid",false,true).unwrap_err().contains("Expired"));}

#[test] fn emsign_root_removed(){let roots=webpki_roots::TLS_SERVER_ROOTS;assert!(roots.len()>100);let bad=b"emSign ECC Root CA - G3";assert!(!roots.iter().any(|a|a.subject.as_ref().windows(bad.len()).any(|s|s==bad)));}
