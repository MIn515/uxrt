#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
pub struct Tag {
    pub typ: u32,
    pub size: u32,
    // tag specific fields
}

#[derive(Clone, Debug)]
pub struct TagIter {
    pub current: *const Tag,
}

impl Iterator for TagIter {
    type Item = &'static Tag;

    fn next(&mut self) -> Option<&'static Tag> {
        match unsafe{&*self.current} {
            &Tag{typ:0, size:8} => None, // end tag
            tag => {
                // go to next tag
                let mut tag_addr = self.current as usize;
                tag_addr += ((tag.size + 7) & !7) as usize; //align at 8 byte
                self.current = tag_addr as *const _;

                Some(tag)
            },
        }
    }
}

