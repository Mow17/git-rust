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
// add BigEndian
use byteorder::BigEndian;
use byteorder::ByteOrder;
// add Utc
use chrono::Utc;


fn main() -> std::io::Result<()> {
    let args: Vec<String> = env::args().collect();
    let message = &args[1];

    let tree_hash = write_tree()?;
    let commit_hash= commit_tree(&tree_hash, message)?;

    println!("{:?}", commit_hash);

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

// function to create tree
fn write_tree() -> std::io::Result<String> {
    // read index as bytes
    let mut path = env::current_dir()?;
    path.push(PathBuf::from(".git/index"));
    let mut file = File::open(path)?;
    let mut buf: Vec<u8> = Vec::new();
    file.read_to_end(&mut buf)?;

    let entry_num = BigEndian::read_u32(&buf[8..12]) as usize;
    let mut start_size = 12 as usize;

    let mut entries: Vec<Vec<u8>> = vec![]; 

    for _ in 0..entry_num {
        // mode: 24 ~ 27
        let mode = BigEndian::read_u32(&buf[(start_size+24)..(start_size+28)]) as u32;
        // hash: 40 ~ 60
        let hash = (&buf[(start_size+40)..(start_size+60)]).to_vec();
        // filename size: 60 ~ 61
        let filename_size = BigEndian::read_u16(&buf[(start_size+60)..(start_size+62)]) as u16;
        // filename: 62 ~ ?
        let filename = (&buf[(start_size+62)..(start_size+62+filename_size as usize)]).to_vec();

        let padding_size = padding(filename_size as usize);
        start_size = start_size + 62 + filename_size as usize + padding_size;

        let entry_header = format!("{:0>6o} {}\0", mode, String::from_utf8(filename).ok().unwrap());
        let entry = [entry_header.as_bytes(), &hash].concat();

        entries.push(entry);
    }

    // make entry together, and concat them with tree header
    let content = entries.concat();
    let header = format!("tree {}\0", content.len());
    let tree_content = [header.as_bytes().to_vec()].concat();

    // buffer for compress
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&tree_content)?;
    let compressed = encoder.finish()?;

    // calculate hash
    let tree_hash = Sha1::digest(&tree_content);
    println!("tree hash: {:x}", tree_hash);
    let hash = format!("{:x}", tree_hash);
    let (dir, file) = hash.split_at(2);

    let mut current_path = env::current_dir()?;
    current_path.push(".git/objects");
    current_path.push(dir);

    let object_dir = current_path.clone();

    fs::create_dir_all(object_dir)?;

    current_path.push(file);
    let object_path = current_path;

    // add contents
    let mut f = File::create(object_path)?;
    f.write_all(&compressed)?;
    f.flush()?;

    Ok(hash)
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

fn update_index(filepath: &str) -> std::io::Result<()> {
    let mut path = env::current_dir()?; // get current dir
    path.push(PathBuf::from(".git/index")); // create absolute path

    let buf = match File::open(path.clone()) {
        Ok(mut f) => {
            let mut buf: Vec<u8> = vec![];
            f.read_to_end(&mut buf)?;
            buf
        },
        Err(_) => {
            vec![]
        }
    };

    if buf == vec![] {
        write_index(vec![filepath])?;
    } else {
        // collect file name in index
        let mut file_paths: Vec<String> = vec![];

        let entry_num = BigEndian::read_u32(&buf[8..12]) as usize;
        let mut start_size = 12 as usize;
        for _ in 0..entry_num {
            // file name size 60 ~ 61
            let filename_size = BigEndian::read_u16(&buf[start_size+60..start_size+62]) as u16;
            // file name 62 ~ 62 + filename_size
            let filename = (&buf[start_size+62..start_size+62+filename_size as usize]).to_vec();

            // calculate padding, and specify next entry bytes
            let padding_size = padding(filename_size as usize);
            start_size += 62 + filename_size as usize + padding_size;

            let filename = String::from_utf8(filename).ok().unwrap();
            file_paths.push(filename);
        }

        // add new file path if not exist
        if !file_paths.iter().any(|e| e == &filepath) {
            file_paths.push(filepath.to_owned());
        }

        // sort file paths to write index
        file_paths.sort();
        // create index with sorted file paths
        write_index(file_paths.iter().map(|s| &**s).collect())?;
    }
    Ok(())
}

fn ls_files() -> std::io::Result<()> {
    // read index as bytes
    let mut path = env::current_dir()?;
    path.push(PathBuf::from(".git/index"));
    let mut file = File::open(path)?;
    let mut buf: Vec<u8> = Vec::new();
    file.read_to_end(&mut buf)?;

    let entry_num = BigEndian::read_u32(&buf[8..12]) as usize;
    let mut start_size = 12 as usize;

    for _ in 0..entry_num {
        // mode: 24 ~ 27
        let mode = BigEndian::read_u32(&buf[(start_size+24)..(start_size+28)]) as u32;
        // hash: 40 ~ 60
        let hash = (&buf[(start_size+40)..(start_size+60)]).to_vec();
        // filename size: 60 ~ 61
        let filename_size = BigEndian::read_u16(&buf[(start_size+60)..(start_size+62)]) as u16;
        // filename: 62 ~ ?
        let filename = (&buf[(start_size+62)..(start_size+62+filename_size as usize)]).to_vec();

        let padding_size = padding(filename_size as usize);
        start_size = start_size + 62 + filename_size as usize + padding_size;

        // no option
        println!("{}", String::from_utf8(filename.clone()).ok().unwrap());
        // -s option
        // println!("{:0>6o} {} 0\t{}", mode, hex::encode(hash), String::from_utf8(filename.clone()).ok().unwrap());
    }

    Ok(())
}

// When reading HEAD, only the very first commit is not hashed, so leave the return value as Option<String>> type.
fn read_head() -> std::io::Result<Option<String>> {
    // HEAD struct is "refs: <branch-path> or <hash>"
    let mut path = env::current_dir()?;
    path.push(PathBuf::from(".git/HEAD"));
    let mut file = File::open(path)?;
    let mut reference = String::new();
    file.read_to_string(&mut reference)?;

    let prefix_path = reference.split(" ").collect::<Vec<&str>>();

    // If HEAD contains a branch name, the hash value of the branch content will be the hash value that HEAD points to.
    if prefix_path[1].contains("/") {
        // branch path is ".git/refs/heads/<branch-name>"
        let mut branch_path = env::current_dir()?;
        branch_path.push(PathBuf::from(".git"));
        // Replace because it contains line breaks
        branch_path.push(PathBuf::from(prefix_path[1].replace("\n", "")));
        println!("{:?}", prefix_path[1]);

        match File::open(branch_path) {
            Ok(mut f) => {
                let mut hash = String::new();
                f.read_to_string(&mut hash)?;
                // Replace because it contains line breaks
                return Ok(Some(hash.replace("\n", "")));
            },
            Err(_) => {
                return Ok(None);
            }
        }
    }
    // if the hash value was stored directly
    Ok(Some(prefix_path[1].replace("\n", "").to_owned()))
}

fn commit_tree(tree_hash: &str, message: &str) -> std::io::Result<Option<String>> {
    let tree_hash = format!("tree {}", tree_hash);

    let author = format!("author {} <{}> {} +0900", 
        "Mow17",
        "Mow17@test.com",
        Utc::now().timestamp()
    );
    let commiter = format!("commiter {} <{}> {} +0900", 
        "Mow17",
        "Mow17@test.com",
        Utc::now().timestamp()
    );

    // The commit in HEAD is the parent commit, so read the hash value of HEAD
    let commit_content = match read_head()? {
        Some(h) => {
            let parent = format!("parent {}", h);
            let content = format!("{}\n{}\n{}\n\n{}\n{}\n", 
                tree_hash, parent, author, commiter, message
            );
            format!("commit {}\0{}", content.len(), content).as_bytes().to_vec()
        },
        _ => {
            let content = format!("{}\n{}\n{}\n\n{}\n", 
                tree_hash, author, commiter, message
            );
            format!("commit {}\0{}", content.len(), content).as_bytes().to_vec()
        }
    };

    // buffer for compressed
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&commit_content)?;
    let compressed = encoder.finish()?;

    // calculate hash
    let commit_hash = Sha1::digest(&commit_content);
    println!("commit hash: {:x}", commit_hash);
    // make hash string
    let hash = format!("{:x}", commit_hash);
    // up to 2 characters of the hash value is the directory path and 38 characters is the file path
    let (dir, file) = hash.split_at(2);

    // Use PathBuf to represent all OS paths.
    let mut current_path = env::current_dir()?;
    current_path.push(".git/objects");
    current_path.push(dir);

    let object_dir = current_path.clone();

    // create directory if not exist
    fs::create_dir_all(object_dir)?;

    current_path.push(file);
    let objact_path = current_path.clone();
    let mut f = File::create(objact_path)?;
    f.write_all(&compressed)?;
    f.flush()?;

    Ok(Some(hash))
}

// Read the `tree` hash from the `commit` hash
fn cat_commit_tree(commit_hash: &str) -> std::io::Result<String> {
    // up to 2 characters of hash: directory path, and 38 characters: file path
    let (dir, file) = commit_hash.split_at(2);

    // get path to the object
    let mut current_path = env::current_dir()?;
    current_path.push(".git/objects");
    current_path.push(dir);
    current_path.push(file);
    let object_path = current_path.clone();

    // open  object and load it in binary
    let mut file = File::open(object_path)?;
    let mut compressed = Vec::new();
    file.read_to_end(&mut compressed)?;

    // decompress compressed data
    let mut decoder = ZlibDecoder::new(&compressed[..]);
    let mut object_content: Vec<u8> = Vec::new();
    decoder.read_to_end(&mut object_content)?;

    // separate header and content with null bytes
    let mut contents = object_content.splitn(2, |&x| x == b'\0');

    // retrieves  second word from  first line, splitting it with space, and returns that string
    let tree = contents.next().and_then(|c| {
        c.split(|&x| x == b'\n')
            .filter(|&x| x.is_empty())
            .map(|x| String::from_utf8_lossy(x).to_string())
            .find_map(|x| x.split_whitespace().nth(1).map(|x| x.to_string()))
    });

    Ok(tree.unwrap())
}
