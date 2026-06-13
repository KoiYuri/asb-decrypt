//! ASB 文件解码库
//!
//! ASB 是一种二进制脚本格式，用于存储标签（label）和指令（instruction）。
//! 本库提供 [`decode_asb`] 函数，将 ASB 二进制数据还原为文本格式。

use std::fmt;

/// 解码过程中可能出现的错误。
#[derive(Debug)]
pub enum DecodeError {
    /// 文件过短，不足以包含完整头部。
    TooShort,
    /// 魔数不是 `ASB\0`。
    BadMagic(Vec<u8>),
    /// 在指定位置数据不足。
    UnexpectedEof { entry: usize, context: String },
    /// 遇到未知的 entry_type。
    UnknownEntryType { entry: usize, value: u32 },
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort => write!(f, "文件过短"),
            Self::BadMagic(bytes) => write!(f, "魔数不匹配: {:02X?}", bytes),
            Self::UnexpectedEof { entry, context } => {
                write!(f, "条目 {entry} {context}: 数据不足")
            }
            Self::UnknownEntryType { entry, value } => {
                write!(f, "条目 {entry}: 未知 entry_type = {value}")
            }
        }
    }
}

impl std::error::Error for DecodeError {}

/// 解码结果，包含还原的文本内容和可能的警告信息。
#[derive(Debug)]
pub struct DecodeResult {
    /// 还原后的脚本文本（行以 `\r\n` 分隔，末尾含 `\r\n`）。
    pub text: String,
    /// 文件末尾残留的字节数（0 表示完全解析）。
    pub trailing_bytes: usize,
}

/// 将 ASB 二进制数据解码为文本格式。
///
/// # 格式说明
///
/// ```text
/// Header:
///   [0..4]  magic: "ASB\0"
///   [4]     flag: u8
///   [5..9]  total_count: u32 LE — 条目总数
///
/// 每条条目:
///   entry_type: u32 LE  (1 = label, 0 = instruction)
///   name_len:   u32 LE
///   name:       [u8; name_len] + null
///
///   若 entry_type == 1 (label)  →  输出 *name
///   若 entry_type == 0 (instruction) →
///     serial:      u32 LE  (丢弃)
///     param_count: u32 LE
///     params[]:
///       key_len: u32 LE, key + null
///       val_len: u32 LE, val + null
///     →  输出 [name key="val" ...] 或 [name]
/// ```
///
/// # Errors
///
/// 当数据格式不合法时返回 [`DecodeError`]。
pub fn decode_asb(data: &[u8]) -> Result<DecodeResult, DecodeError> {
    if data.len() < 9 {
        return Err(DecodeError::TooShort);
    }

    let magic = &data[0..4];
    if magic != b"ASB\x00" {
        return Err(DecodeError::BadMagic(magic.to_vec()));
    }

    let mut r = Reader::new(data);
    r.pos = 4;
    let _flag = r.read_u8();
    let total = r.read_u32_le() as usize;

    let mut lines: Vec<String> = Vec::with_capacity(total);

    for i in 0..total {
        if r.remaining() < 8 {
            return Err(DecodeError::UnexpectedEof {
                entry: i,
                context: "条目头部".into(),
            });
        }

        let entry_type = r.read_u32_le();
        let name_len = r.read_u32_le() as usize;

        if r.remaining() < name_len + 1 {
            return Err(DecodeError::UnexpectedEof {
                entry: i,
                context: "名称".into(),
            });
        }
        let name = r.read_string(name_len);

        match entry_type {
            1 => {
                lines.push(format!("*{name}"));
            }
            0 => {
                if r.remaining() < 8 {
                    return Err(DecodeError::UnexpectedEof {
                        entry: i,
                        context: format!("[{name}] serial/param_count"),
                    });
                }
                let _serial = r.read_u32_le();
                let param_count = r.read_u32_le() as usize;

                let mut params: Vec<String> = Vec::with_capacity(param_count);
                for j in 0..param_count {
                    if r.remaining() < 8 {
                        return Err(DecodeError::UnexpectedEof {
                            entry: i,
                            context: format!("[{name}] 参数 {j}"),
                        });
                    }
                    let kl = r.read_u32_le() as usize;
                    let key = r.read_string(kl);
                    let vl = r.read_u32_le() as usize;
                    let val = r.read_string(vl);
                    params.push(format!("{key}=\"{val}\""));
                }

                if params.is_empty() {
                    lines.push(format!("[{name}]"));
                } else {
                    lines.push(format!("[{name} {}]", params.join(" ")));
                }
            }
            other => {
                return Err(DecodeError::UnknownEntryType {
                    entry: i,
                    value: other,
                });
            }
        }
    }

    let trailing = r.remaining();
    let text = lines.join("\r\n") + "\r\n";

    Ok(DecodeResult {
        text,
        trailing_bytes: trailing,
    })
}

/// 便捷函数：解码并返回文本字符串，忽略尾部残留字节。
pub fn decode_asb_to_string(data: &[u8]) -> Result<String, DecodeError> {
    decode_asb(data).map(|r| r.text)
}

// ── 内部读取器 ──────────────────────────────────────────────

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Reader { data, pos: 0 }
    }

    fn read_u8(&mut self) -> u8 {
        let v = self.data[self.pos];
        self.pos += 1;
        v
    }

    fn read_u32_le(&mut self) -> u32 {
        let bytes: [u8; 4] = self.data[self.pos..self.pos + 4].try_into().unwrap();
        self.pos += 4;
        u32::from_le_bytes(bytes)
    }

    /// 读取 `len` 字节的字符串，再跳过 1 字节 null 终止符。
    fn read_string(&mut self, len: usize) -> String {
        let bytes = &self.data[self.pos..self.pos + len];
        self.pos += len + 1;
        String::from_utf8_lossy(bytes).into_owned()
    }

    fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bad_magic_rejected() {
        let data = b"XXB\x00\x00\x01\x00\x00\x00";
        let err = decode_asb(data).unwrap_err();
        assert!(matches!(err, DecodeError::BadMagic(_)));
    }

    #[test]
    fn too_short_rejected() {
        let data = b"ASB";
        assert!(matches!(decode_asb(data), Err(DecodeError::TooShort)));
    }

    /// 构造一个最小的 ASB 二进制并验证解码结果。
    ///
    /// 内容等价于:
    /// ```text
    /// *main
    /// [jump label="start"]
    /// *start
    /// [return]
    /// ```
    #[test]
    fn decode_minimal_asb() {
        let mut buf: Vec<u8> = Vec::new();

        // Header: magic + flag + total_count(4)
        buf.extend_from_slice(b"ASB\x00");
        buf.push(0x00); // flag
        buf.extend_from_slice(&4u32.to_le_bytes()); // 4 entries

        // Entry 0: label "main"
        buf.extend_from_slice(&1u32.to_le_bytes()); // type = label
        buf.extend_from_slice(&4u32.to_le_bytes()); // name_len
        buf.extend_from_slice(b"main");
        buf.push(0x00);

        // Entry 1: instruction "jump" with param label="start"
        buf.extend_from_slice(&0u32.to_le_bytes()); // type = instruction
        buf.extend_from_slice(&4u32.to_le_bytes()); // name_len
        buf.extend_from_slice(b"jump");
        buf.push(0x00);
        buf.extend_from_slice(&0u32.to_le_bytes()); // serial
        buf.extend_from_slice(&1u32.to_le_bytes()); // param_count
        // param: key="label", val="start"
        buf.extend_from_slice(&5u32.to_le_bytes());
        buf.extend_from_slice(b"label");
        buf.push(0x00);
        buf.extend_from_slice(&5u32.to_le_bytes());
        buf.extend_from_slice(b"start");
        buf.push(0x00);

        // Entry 2: label "start"
        buf.extend_from_slice(&1u32.to_le_bytes());
        buf.extend_from_slice(&5u32.to_le_bytes());
        buf.extend_from_slice(b"start");
        buf.push(0x00);

        // Entry 3: instruction "return" (no params)
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&6u32.to_le_bytes());
        buf.extend_from_slice(b"return");
        buf.push(0x00);
        buf.extend_from_slice(&0u32.to_le_bytes()); // serial
        buf.extend_from_slice(&0u32.to_le_bytes()); // param_count

        let result = decode_asb(&buf).unwrap();
        assert_eq!(result.trailing_bytes, 0);
        assert_eq!(
            result.text,
            "*main\r\n[jump label=\"start\"]\r\n*start\r\n[return]\r\n"
        );
    }
}

#[test]
fn decode_script_asb_show() {
    let data = std::fs::read("/Users/alphaly/lfpm/loli/root/system/script.asb").unwrap();
    let text = crate::decode_asb_to_string(&data).unwrap();
    panic!("DECODED:\n{}", &text[..text.len().min(5000)]);
}

#[cfg(test)]
mod decode_tests {
    #[test]
    fn decode_script_asb_show() {
        let data = std::fs::read(
            "/Users/alphaly/RustroverProjects/art3m1s-core/example/project/system/script.asb",
        )
        .unwrap();
        let text = crate::decode_asb_to_string(&data).unwrap();
        panic!("DECODED:\n{}", &text[..text.len().min(3000)]);
    }
}
