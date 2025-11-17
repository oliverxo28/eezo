#![cfg(feature = "gpu-hash")]

// ======================================================================
// T44.4 — GPU hashing (wgpu) context + compute pipeline stub
//
// This module is structured so that:
//
//  - By default (no env vars), it does *not* touch wgpu at all and
//    behaves as a CPU-only hashing backend. This keeps `cargo test`
//    stable on machines without a working GPU or driver.
//
//  - When the environment variable `EEZO_GPU_HASH_REAL=1` is set,
//    we attempt to initialize a real wgpu Instance/Adapter/Device/Queue,
//    and we also compile a tiny WGSL compute shader into a
//    `wgpu::ComputePipeline`.
//
// hash_many() is STILL a CPU fallback (direct BLAKE3), so there is no
// change to cryptographic behavior yet.
// ======================================================================
use anyhow::{anyhow, Result};
use blake3;
use log::{info, warn};
use std::env;
use std::fmt;
use std::sync::OnceLock;

/// For now we just alias to anyhow::Error. This keeps the surface small
/// while we experiment with wgpu; we can always introduce a richer
/// error type later if needed.
pub type GpuError = anyhow::Error;

/// BLAKE3 output length in bytes.
const BLAKE3_OUT_LEN: usize = 32;

/// For T46.1 we only consider attempting GPU hashing for messages
/// that fit in a single BLAKE3 chunk (64 bytes). Anything larger
/// stays on the CPU path for now.
const MAX_GPU_MSG_LEN: usize = 64;

/// A handle to the GPU BLAKE3 backend.
///
/// For T44.4 this optionally owns:
///   - `wgpu::Device`
///   - `wgpu::Queue`
///   - `wgpu::ComputePipeline` (a stub compute shader)
///
/// When running without a real GPU (or without the env flag), it
/// simply runs in CPU-only mode with all fields set to None.
pub struct GpuBlake3Context {
    device: Option<wgpu::Device>,
    queue: Option<wgpu::Queue>,
    pipeline: Option<wgpu::ComputePipeline>,
}

impl fmt::Debug for GpuBlake3Context {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GpuBlake3Context")
            .field(
                "device",
                &if self.device.is_some() {
                    "Some(wgpu::Device{…})"
                } else {
                    "None"
                },
            )
            .field(
                "queue",
                &if self.queue.is_some() {
                    "Some(wgpu::Queue{…})"
                } else {
                    "None"
                },
            )
            .field(
                "pipeline",
                &if self.pipeline.is_some() {
                    "Some(wgpu::ComputePipeline{…})"
                } else {
                    "None"
                },
            )
            .finish()
    }
}

/// Description of a GPU BLAKE3 batch (host view).
///
/// The contract is:
///   - `offsets.len() == lens.len() == N`
///   - `digests_out.len() == N * 32`
///   - for all i: `offsets[i] + lens[i] <= input_blob.len()`
pub struct Blake3GpuBatch<'a> {
    /// All message bytes concatenated.
    pub input_blob: &'a [u8],

    /// Start offset (into `input_blob`) for each message.
    pub offsets: &'a [u32],

    /// Length of each message in bytes.
    pub lens: &'a [u32],

    /// Output buffer: must be `N * 32` bytes long.
    pub digests_out: &'a mut [u8],
}

/// Trait implemented by any GPU backend (CUDA, wgpu, etc.).
pub trait Blake3GpuBackend {
    /// Hash N messages using BLAKE3 on the GPU.
    ///
    /// Implementations must respect the invariants of `Blake3GpuBatch`.
    fn hash_batch(&self, batch: &mut Blake3GpuBatch<'_>) -> Result<(), GpuError>;
}

/// Engine used by higher layers. They don't care if this is CPU or GPU;
/// they just ask for batch hashing.
pub enum Blake3BatchEngine {
    /// Pure CPU path (direct BLAKE3).
    Cpu,
    /// GPU-backed path via a dynamic backend implementation.
    Gpu(Box<dyn Blake3GpuBackend + Send + Sync>),
}

impl Blake3BatchEngine {
    /// Hash a batch of messages according to the `Blake3GpuBatch` contract.
    pub fn hash_batch(&self, batch: &mut Blake3GpuBatch<'_>) -> Result<(), GpuError> {
        match self {
            Blake3BatchEngine::Cpu => cpu_hash_batch(batch),
            Blake3BatchEngine::Gpu(backend) => backend.hash_batch(batch),
        }
    }
}

/// Global default batch engine, decided once per process.
///
/// Logic:
///   - If `EEZO_GPU_HASH_REAL != "1"`, we use CPU.
///   - If it *is* "1", we attempt to initialize a `GpuBlake3Context`.
///     If that works and is usable, we use GPU; otherwise we log and
///     fall back to CPU.
static BATCH_ENGINE: OnceLock<Blake3BatchEngine> = OnceLock::new();

/// Return the default batch engine (CPU or GPU), initialized on first use.
pub fn default_batch_engine() -> &'static Blake3BatchEngine {
    BATCH_ENGINE.get_or_init(|| {
        let want_real = env::var("EEZO_GPU_HASH_REAL")
            .ok()
            .map(|s| s == "1")
            .unwrap_or(false);

        if !want_real {
            info!("gpu-hash: EEZO_GPU_HASH_REAL != \"1\"; using CPU batch engine");
            return Blake3BatchEngine::Cpu;
        }

        match GpuBlake3Context::new() {
            Ok(ctx) if ctx.is_available() => {
                info!("gpu-hash: GPU context available; using GPU batch engine");
                Blake3BatchEngine::Gpu(Box::new(ctx))
            }
            Ok(_) => {
                warn!("gpu-hash: GPU context initialized but not usable; falling back to CPU");
                Blake3BatchEngine::Cpu
            }
            Err(e) => {
                warn!(
                    "gpu-hash: failed to initialize GpuBlake3Context ({e}); falling back to CPU"
                );
                Blake3BatchEngine::Cpu
            }
        }
    })
}

/// Front-door helper for batch hashing with metrics + optional
/// CPU-vs-GPU cross-check (controlled by env vars).
///
/// Env knobs:
///   - `EEZO_GPU_HASH_CHECK=1`:
///         run GPU + CPU and compare digests.
///         On mismatch: increment GPU_HASH_MISMATCH_TOTAL and
///         optionally error out if `EEZO_GPU_HASH_STRICT=1`.
///
///   - `EEZO_GPU_HASH_STRICT=1`:
///         in compare mode, treat any mismatch as a hard error.
///
/// Metrics:
///   - `GPU_HASH_ATTEMPTS_TOTAL`:
///         incremented for every GPU batch attempt (engine = Gpu).
///   - `GPU_HASH_FALLBACKS_TOTAL`:
///         incremented when GPU hashing fails and we fall back to CPU.
///   - `GPU_HASH_COMPARE_TOTAL`:
///         incremented when compare mode is active.
///   - `GPU_HASH_MISMATCH_TOTAL`:
///         incremented if GPU and CPU digests differ.
pub fn hash_batch_with_metrics(batch: &mut Blake3GpuBatch<'_>) -> Result<(), GpuError> {
    let engine = default_batch_engine();

    match engine {
        // Pure CPU engine: no GPU metrics; just use the reference path.
        Blake3BatchEngine::Cpu => cpu_hash_batch(batch),

        Blake3BatchEngine::Gpu(backend) => {
            crate::metrics::GPU_HASH_ATTEMPTS_TOTAL.inc();

            let check_mode = env::var("EEZO_GPU_HASH_CHECK")
                .ok()
                .map(|s| s == "1")
                .unwrap_or(false);

            // Fast path: GPU only, with CPU fallback on error.
            if !check_mode {
                match backend.hash_batch(batch) {
                    Ok(()) => Ok(()),
                    Err(e) => {
                        crate::metrics::GPU_HASH_FALLBACKS_TOTAL.inc();
                        warn!(
                            "gpu-hash: GPU batch hashing failed ({e}); falling back to CPU"
                        );
                        cpu_hash_batch(batch)
                    }
                }
            } else {
                // Compare mode: run GPU into a temp buffer, CPU into the caller's buffer.
                crate::metrics::GPU_HASH_COMPARE_TOTAL.inc();

                let n = batch.offsets.len();
                let mut gpu_out = vec![0u8; n * BLAKE3_OUT_LEN];

                // 1) GPU into gpu_out (temp)
                {
                    let mut gpu_batch = Blake3GpuBatch {
                        input_blob: batch.input_blob,
                        offsets: batch.offsets,
                        lens: batch.lens,
                        digests_out: &mut gpu_out,
                    };

                    if let Err(e) = backend.hash_batch(&mut gpu_batch) {
                        crate::metrics::GPU_HASH_FALLBACKS_TOTAL.inc();
                        warn!(
                            "gpu-hash: GPU batch hashing failed in compare mode ({e}); falling back to CPU"
                        );
                        return cpu_hash_batch(batch);
                    }
                }

                // 2) CPU reference into the caller's buffer.
                cpu_hash_batch(batch)?;

                // 3) Compare digests.
                if gpu_out != batch.digests_out {
                    crate::metrics::GPU_HASH_MISMATCH_TOTAL.inc();
                    log::error!(
                        "gpu-hash: GPU/CPU mismatch detected in compare mode (EEZO_GPU_HASH_CHECK=1)"
                    );

                    let strict = env::var("EEZO_GPU_HASH_STRICT")
                        .ok()
                        .map(|s| s == "1")
                        .unwrap_or(false);

                    if strict {
                        return Err(anyhow!(
                            "gpu-hash: GPU/CPU mismatch in strict compare mode"
                        ));
                    }
                }

                Ok(())
            }
        }
    }
}

/// Internal helper: basic safety checks on the batch metadata.
fn validate_batch(batch: &Blake3GpuBatch<'_>) -> Result<(), GpuError> {
    let n = batch.offsets.len();

    if n == 0 {
        return Err(anyhow!("gpu-hash: empty batch is not allowed"));
    }
    if batch.lens.len() != n {
        return Err(anyhow!(
            "gpu-hash: lens.len()={} does not match offsets.len()={}",
            batch.lens.len(),
            n
        ));
    }

    let expected_out = n
        .checked_mul(BLAKE3_OUT_LEN)
        .ok_or_else(|| anyhow!("gpu-hash: digest buffer size overflow"))?;
    if batch.digests_out.len() != expected_out {
        return Err(anyhow!(
            "gpu-hash: digests_out.len()={} but expected {} (= {} * {})",
            batch.digests_out.len(),
            expected_out,
            n,
            BLAKE3_OUT_LEN
        ));
    }

    let total_len = batch.input_blob.len();
    for i in 0..n {
        let off = batch.offsets[i] as usize;
        let len = batch.lens[i] as usize;
        let end = off
            .checked_add(len)
            .ok_or_else(|| anyhow!("gpu-hash: offset/length overflow at index {i}"))?;

        if end > total_len {
            return Err(anyhow!(
                "gpu-hash: message {i} (off={} len={}) exceeds input_blob.len()={}",
                off,
                len,
                total_len
            ));
        }
    }

    Ok(())
}

/// Internal helper: CPU implementation of the batch hashing contract.
fn cpu_hash_batch(batch: &mut Blake3GpuBatch<'_>) -> Result<(), GpuError> {
    validate_batch(batch)?;

    let n = batch.offsets.len();
    for i in 0..n {
        let off = batch.offsets[i] as usize;
        let len = batch.lens[i] as usize;
        let end = off + len;
        let msg = &batch.input_blob[off..end];

        let digest = blake3::hash(msg);
        let out_slice = &mut batch.digests_out[i * BLAKE3_OUT_LEN..(i + 1) * BLAKE3_OUT_LEN];
        out_slice.copy_from_slice(digest.as_bytes());
    }

    Ok(())
}
impl GpuBlake3Context {
    /// Initialize the context.
    ///
    /// Default behavior:
    ///   - If `EEZO_GPU_HASH_REAL` is *not* set to `"1"`, we skip real
    ///     wgpu initialization entirely and return a CPU-only context.
    ///
    /// Explicit GPU mode:
    ///   - If `EEZO_GPU_HASH_REAL=1`, we attempt real wgpu init
    ///     (Instance → Adapter → Device/Queue) and also build a stub
    ///     compute pipeline. On any failure we log a warning and still
    ///     return a CPU-only context, so the prover can continue.
    pub fn new() -> Result<Self, GpuError> {
        let env_flag = env::var("EEZO_GPU_HASH_REAL").unwrap_or_default();

        if env_flag != "1" {
            info!(
                "gpu-hash: EEZO_GPU_HASH_REAL != '1'; using CPU-only context (no wgpu init)"
            );
            return Ok(GpuBlake3Context {
                device: None,
                queue: None,
                pipeline: None,
            });
        }

        info!("gpu-hash: EEZO_GPU_HASH_REAL=1; attempting real wgpu init");

        let instance = wgpu::Instance::default();

        let adapter = match pollster::block_on(instance.request_adapter(
            &wgpu::RequestAdapterOptions {
                power_preference: wgpu::PowerPreference::HighPerformance,
                compatible_surface: None,
                force_fallback_adapter: false,
            },
        )) {
            Some(a) => a,
            None => {
                warn!("gpu-hash: failed to find a suitable GPU adapter; falling back to CPU");
                return Ok(GpuBlake3Context {
                    device: None,
                    queue: None,
                    pipeline: None,
                });
            }
        };

        let info = adapter.get_info();
        info!(
            "gpu-hash: selected adapter '{}', backend={:?}, device_type={:?}",
            info.name, info.backend, info.device_type
        );

        let (device, queue) = match pollster::block_on(adapter.request_device(
            &wgpu::DeviceDescriptor {
                label: Some("eezo-blake3-gpu-device"),
                // wgpu 0.19: use required_features / required_limits
                required_features: wgpu::Features::empty(),
                required_limits: wgpu::Limits::downlevel_defaults(),
            },
            None,
        )) {
            Ok(pair) => pair,
            Err(e) => {
                warn!("gpu-hash: device creation failed: {e}; falling back to CPU");
                return Ok(GpuBlake3Context {
                    device: None,
                    queue: None,
                    pipeline: None,
                });
            }
        };

        // ------------------------------------------------------------------
        // T46.2a: compile a WGSL compute shader with a *real* buffer layout.
        //
        // This version still uses a stub body (it just zeroes out the digest
        // words for each message), but:
        //   - we now define storage buffers for input_words, offsets, lens,
        //     and digests_out
        //   - the pipeline layout has a proper bind group layout
        //
        // Later T46.x steps will replace the body with real single-chunk
        // BLAKE3 compression, under CPU cross-check.
        // ------------------------------------------------------------------
        let shader_src = r#"
            struct InputWords {
                data: array<u32>;
            };

            struct Offsets {
                data: array<u32>;
            };

            struct Lens {
                data: array<u32>;
            };

            struct Digests {
                data: array<u32>;
            };

            @group(0) @binding(0)
            var<storage, read> input_words: InputWords;

            @group(0) @binding(1)
            var<storage, read> offsets: Offsets;

            @group(0) @binding(2)
            var<storage, read> lens: Lens;

            @group(0) @binding(3)
            var<storage, read_write> digests: Digests;

            @compute @workgroup_size(1)
            fn main(@builtin(global_invocation_id) gid : vec3<u32>) {
                let i: u32 = gid.x;

                // For now this is still a stub: we just zero out the 8-word
                // digest slot for this message. Later we will replace this
                // with a real single-chunk BLAKE3 compression.
                let base: u32 = i * 8u;
                var j: u32 = 0u;
                loop {
                    if (j >= 8u) {
                        break;
                    }
                    digests.data[base + j] = 0u;
                    j = j + 1u;
                }
            }
        "#;

        let shader = device.create_shader_module(wgpu::ShaderModuleDescriptor {
            label: Some("eezo-blake3-gpu-shader"),
            source: wgpu::ShaderSource::Wgsl(shader_src.into()),
        });

        let bind_group_layout = device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
            label: Some("eezo-blake3-gpu-bind-group-layout"),
            entries: &[
                wgpu::BindGroupLayoutEntry {
                    binding: 0,
                    visibility: wgpu::ShaderStages::COMPUTE,
                    ty: wgpu::BindingType::Buffer {
                        ty: wgpu::BufferBindingType::Storage { read_only: true },
                        has_dynamic_offset: false,
                        min_binding_size: None,
                    },
                    count: None,
                },
                wgpu::BindGroupLayoutEntry {
                    binding: 1,
                    visibility: wgpu::ShaderStages::COMPUTE,
                    ty: wgpu::BindingType::Buffer {
                        ty: wgpu::BufferBindingType::Storage { read_only: true },
                        has_dynamic_offset: false,
                        min_binding_size: None,
                    },
                    count: None,
                },
                wgpu::BindGroupLayoutEntry {
                    binding: 2,
                    visibility: wgpu::ShaderStages::COMPUTE,
                    ty: wgpu::BindingType::Buffer {
                        ty: wgpu::BufferBindingType::Storage { read_only: true },
                        has_dynamic_offset: false,
                        min_binding_size: None,
                    },
                    count: None,
                },
                wgpu::BindGroupLayoutEntry {
                    binding: 3,
                    visibility: wgpu::ShaderStages::COMPUTE,
                    ty: wgpu::BindingType::Buffer {
                        ty: wgpu::BufferBindingType::Storage { read_only: false },
                        has_dynamic_offset: false,
                        min_binding_size: None,
                    },
                    count: None,
                },
            ],
        });

        let pipeline_layout = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
            label: Some("eezo-blake3-gpu-pipeline-layout"),
            bind_group_layouts: &[&bind_group_layout],
            push_constant_ranges: &[],
        });

        let pipeline = device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
            label: Some("eezo-blake3-gpu-pipeline"),
            layout: Some(&pipeline_layout),
            module: &shader,
            entry_point: "main",
        });

        info!("gpu-hash: compute pipeline with buffer layout created");


        Ok(GpuBlake3Context {
            device: Some(device),
            queue: Some(queue),
            pipeline: Some(pipeline),
        })
    }

    /// For T44.4 this is still a CPU fallback (direct BLAKE3), so we
    /// can start using this interface before the real GPU kernel is
    /// implemented in later T44.x steps.
    pub fn hash_many<'a, I>(&self, inputs: I) -> Result<Vec<[u8; 32]>, GpuError>
    where
        I: IntoIterator<Item = &'a [u8]>,
    {
        let digests = inputs
            .into_iter()
            .map(|bytes| *blake3::hash(bytes).as_bytes())
            .collect();

        Ok(digests)
    }

    /// Convenience helper: is the GPU path actually usable?
    ///
    /// Right now this checks that we have a device, queue and pipeline.
    pub fn is_available(&self) -> bool {
        self.device.is_some() && self.queue.is_some() && self.pipeline.is_some()
    }
}
/// For T46.2a, the GPU backend implementation still uses the CPU
/// helper for the actual BLAKE3 digests (no behaviour change), but
/// it now exercises a *real* buffer layout:
///   - storage buffers for input_words, offsets, lens, digests_out
///   - a bind group that matches the WGSL shader
///
/// The WGSL body is still a stub (zeroing the digest slots), so GPU
/// output is not used yet. This is a safe staging step before we
/// implement real BLAKE3 in WGSL.
impl Blake3GpuBackend for GpuBlake3Context {
    fn hash_batch(&self, batch: &mut Blake3GpuBatch<'_>) -> Result<(), GpuError> {
        // Always compute the correct digests on CPU. This keeps behaviour
        // identical to pre-GPU runs and makes CPU the source of truth
        // while we evolve the kernel.
        cpu_hash_batch(batch)?;

        // If there is no usable GPU context, we are done.
        let device = match &self.device {
            Some(d) => d,
            None => return Ok(()),
        };
        let queue = match &self.queue {
            Some(q) => q,
            None => return Ok(()),
        };
        let pipeline = match &self.pipeline {
            Some(p) => p,
            None => return Ok(()),
        };

        let n = batch.offsets.len();
        if n == 0 {
            // validate_batch() already rejected this, but be defensive.
            return Ok(());
        }

        // T46.1: only exercise the GPU path when all messages are
        // single-chunk sized (<= 64 bytes). Larger messages remain
        // pure CPU for now.
        let all_single_chunk = batch
            .lens
            .iter()
            .all(|&len| (len as usize) <= MAX_GPU_MSG_LEN);
        if !all_single_chunk {
            return Ok(());
        }

        // For now we don't actually use the real message bytes on the GPU;
        // the kernel body is still a stub. But we allocate buffers with
        // realistic sizes to validate memory layout and binding.
        //
        // input_words: one "chunk" (16 words) per message.
        let input_words_len = n * 16;
        let input_words_bytes = (input_words_len * std::mem::size_of::<u32>()) as u64;

        let input_words_buf = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("eezo-blake3-gpu-input-words"),
            size: input_words_bytes.max(4), // avoid zero-sized buffer
            usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });

        // offsets + lens: one u32 per message.
        let meta_len = n;
        let meta_bytes = (meta_len * std::mem::size_of::<u32>()) as u64;

        // offsets buffer (currently just copies the existing offsets).
        let offsets_buf = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("eezo-blake3-gpu-offsets"),
            size: meta_bytes.max(4),
            usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });

        if meta_len > 0 {
            // write offsets as little-endian u32 to the GPU buffer
            let mut tmp = Vec::with_capacity(meta_len * 4);
            for &off in batch.offsets {
                tmp.extend_from_slice(&(off as u32).to_le_bytes());
            }
            queue.write_buffer(&offsets_buf, 0, &tmp);
        }

        // lens buffer (currently just copies the existing lens).
        let lens_buf = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("eezo-blake3-gpu-lens"),
            size: meta_bytes.max(4),
            usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });

        if meta_len > 0 {
            let mut tmp = Vec::with_capacity(meta_len * 4);
            for &len in batch.lens {
                tmp.extend_from_slice(&(len as u32).to_le_bytes());
            }
            queue.write_buffer(&lens_buf, 0, &tmp);
        }

        // digests buffer: 8 u32 words per message (32 bytes).
        let digest_words_len = n * 8;
        let digest_bytes = (digest_words_len * std::mem::size_of::<u32>()) as u64;

        let digests_buf = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("eezo-blake3-gpu-digests"),
            size: digest_bytes.max(4),
            usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });

        // Bind group matching the shader layout.
        let bind_group_layout = pipeline.get_bind_group_layout(0);
        let bind_group = device.create_bind_group(&wgpu::BindGroupDescriptor {
            label: Some("eezo-blake3-gpu-bind-group"),
            layout: &bind_group_layout,
            entries: &[
                wgpu::BindGroupEntry {
                    binding: 0,
                    resource: input_words_buf.as_entire_binding(),
                },
                wgpu::BindGroupEntry {
                    binding: 1,
                    resource: offsets_buf.as_entire_binding(),
                },
                wgpu::BindGroupEntry {
                    binding: 2,
                    resource: lens_buf.as_entire_binding(),
                },
                wgpu::BindGroupEntry {
                    binding: 3,
                    resource: digests_buf.as_entire_binding(),
                },
            ],
        });

        let mut encoder = device.create_command_encoder(&wgpu::CommandEncoderDescriptor {
            label: Some("eezo-blake3-gpu-encoder"),
        });

        {
            let mut cpass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
                label: Some("eezo-blake3-gpu-pass"),
                timestamp_writes: None,
            });
            cpass.set_pipeline(pipeline);
            cpass.set_bind_group(0, &bind_group, &[]);
            // One invocation per message.
            cpass.dispatch_workgroups(n as u32, 1, 1);
        }

        queue.submit(Some(encoder.finish()));

        Ok(())
    }
}
