// method with env
use std::env;
use std::os::unix::fs::MetadataExt;
// Pathbuf struct
use std::path::PathBuf;
// File struct
use std::fs::File;
// add module
use std::io::prelude::*;
// include sha1
use sha1::{Digest, Sha1};
// add fs
use std::fs;
// crates for decompress
use flate2::Compression;
use flate2::write::ZlibEncoder;
use flate2::read::ZlibDecoder;


fn main() -> std::io::Result<()> {
    write_index(vec!["first.txt", "second.txt"])?;

    Ok(())
}

fn create_entry(filename: &str) -> std::io::Result<Vec<u8>> {
    // create PathBuf struct from path name
    let mut path = env::current_dir()?;
    path.push(PathBuf::from(filename));

    // metadata structures can be retrieved with trait
    let metadata = path.metadata()?;

    let ctime = metadata.ctime() as u32;
    let ctime_nsec = metadata.ctime_nsec() as u32;
    let mtime = metadata.mtime() as u32;
    let mtime_nsec = metadata.mtime_nsec() as u32;
    let dev = metadata.dev() as u32;
    let ino = metadata.ino() as u32;
    let mode = metadata.mode() as u32;
    let uid = metadata.uid() as u32;
    let gid = metadata.gid() as u32;
    let filesize = metadata.size() as u32;

    // hash value of blob
    let mut f = File::open(path)?;
    let mut content = String::new();
    f.read_to_string(&mut content)?;
    let blob_content = format!("blob {}\0{}", content.len(), content);
    let blob_hash = Sha1::digest(blob_content.as_bytes());
    let hash = blob_hash.as_slice();

    // size of filename
    let filename_size = filename.len() as u16;
    // padding size
    let padding_size = padding(filename_size as usize);
    let padding = vec![b'\0'; padding_size];

    // connect every contents as byte
    let entry_meta = [ctime.to_be_bytes(), ctime_nsec.to_be_bytes(),
        mtime.to_be_bytes(), mtime_nsec.to_be_bytes(), dev.to_be_bytes(),
        ino.to_be_bytes(), mode.to_be_bytes(), uid.to_be_bytes(),
        gid.to_be_bytes(), filesize.to_be_bytes()].concat();
    
    let filemeta_vec = [entry_meta, hash.to_vec(), Vec::from(filename_size.to_be_bytes()),
        filename.as_bytes().to_vec(), padding].concat();
    
    Ok(filemeta_vec)
}

fn padding(size: usize) -> usize {
    // calculate padding size
    let floor = (size - 2) / 8;
    let target = (floor + 1) * 8 + 2;
    let padding = target - size;

    padding
}

// function to create index
fn write_index(filenames: Vec<&str>) -> std::io::Result<()> {
    // bind variable that will contain contents
    let mut content: Vec<Vec<u8>> = vec![];

    // collect header parts as bytes
    let index_header = b"DIRC";
    let index_version = 2 as u32;
    let entry_num = filenames.len() as u32;
    let header = [*index_header, index_version.to_be_bytes(), entry_num.to_be_bytes()].concat();
    content.push(header);

    // collect entry parts as bytes
    for filename in filenames {
        let entry = create_entry(filename)?;
        content.push(entry);
    }

    let mut path = env::current_dir()?;
    path.push(PathBuf::from(".git/index"));
    let mut file = File::create(path)?;
    file.write_all(content.concat().as_slice())?;
    file.flush()?;

    Ok(())
}

fn cat_blob(hash: &str) -> std::io::Result<()> {
    // up to 2 characters of hash: directory path, 38 characters: file path
    let (dir, file) = hash.split_at(2);

    // Specify destination with absolute path
    let mut current_path = env::current_dir()?; // path/git-rust/
    current_path.push(".git/objects"); // path/git-rust/.git/objects/
    current_path.push(dir); // e.g. path/git-rust/.git/objects/b4/ 
    current_path.push(file);
    let object_path = current_path.clone();

    // open object and read binary
    let mut compressed = Vec::new();
    let mut file = File::open(object_path)?;
    file.read_to_end(&mut compressed)?;

    // decompress compressed data
    let mut object_content: Vec<u8> = Vec::new();
    let mut decoder = ZlibDecoder::new(&compressed[..]);
    decoder.read_to_end(&mut object_content)?;

    // separate HEADER and CONTENT with null bytes.
    let mut contents = object_content.splitn(2, |&x| x == b'\0');
    println!("header:\n{}", String::from_utf8(contents.next().unwrap().to_vec()).ok().unwrap());
    println!("file content:\n{}", String::from_utf8(contents.next().unwrap().to_vec()).ok().unwrap());

    Ok(())
}

fn write_blob(filename: &str) -> std::io::Result<()> {
    // check the content of file
    let mut path = env::current_dir()?; // get current dir
    path.push(PathBuf::from(filename)); // create absolute path

    let mut f = File::open(path)?; // open file
    let mut content = String::new(); // buffer to store data
    f.read_to_string(&mut content)?; // write in buffer

    // object is constructed with 'header' + '\0' + 'content'
    let blob_content = format!("blob {}\0{}", content.len(), content); // content.len() expressed byte (not length)
    println!("blob content {}", blob_content);

    // calculate hash
    let blob_hash = Sha1::digest(blob_content.as_bytes());
    println!("blob hash {:x}", blob_hash);

    // prepare buffer for decompress
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    
    encoder.write_all(&blob_content.as_bytes())?;
    let compressed = encoder.finish()?;

    // convert hash to str
    let hash = format!("{:x}", blob_hash);
    // up to 2 characters of hash: directory path, 38 characters: file path
    let (dir, file) = hash.split_at(2);

    // Specify destination with absolute path
    let mut current_path = env::current_dir()?; // path/git-rust/
    current_path.push(".git/objects"); // path/git-rust/.git/objects/
    current_path.push(dir); // e.g. path/git-rust/.git/objects/b4/ 

    let object_dir = current_path.clone();

    // create dir
    fs::create_dir_all(object_dir)?;
    current_path.push(file);
    let object_path = current_path;
    let mut f = File::create(object_path)?;
    f.write_all(&compressed)?;
    f.flush()?;

    Ok(())
}
