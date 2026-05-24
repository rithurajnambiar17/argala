pub mod destructive_os_guard;
pub mod database_guard;
pub mod jailbreak_guard;
pub mod resource_exhaustion_guard;
pub mod pii_leakage_guard;

use crate::plugins::destructive_os_guard::DestructiveOsGuard;
use crate::plugins::database_guard::DatabaseGuard;
use crate::plugins::jailbreak_guard::JailbreakGuard;
use crate::plugins::resource_exhaustion_guard::ResourceExhaustionGuard;
use crate::plugins::pii_leakage_guard::PiiLeakageGuard;

pub fn get_default_plugins() -> Vec<Box<dyn SecurityPlugin>> {
    vec![
        Box::new(DestructiveOsGuard::new()),
        Box::new(DatabaseGuard::new()),
        Box::new(JailbreakGuard::new()),
        Box::new(ResourceExhaustionGuard::new()),
        Box::new(PiiLeakageGuard::new()),
    ]
}

use pyo3::create_exception;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList, PyModule, PyTuple, PyType};
use regex::{Regex, RegexBuilder};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::fs;

pub mod plugins;

create_exception!(argala, ArgalaSecurityViolation, pyo3::exceptions::PyException);

// =====================================================================
// 1. THE OPEN-SOURCE EXTENSION INTERFACE
// =====================================================================
pub trait SecurityPlugin: Send + Sync {
    fn name(&self) -> &str;
    fn validate(&self, method_name: &str, args: &[String]) -> Result<(), String>;
    // New optional trait method to allow plugins to scrub exfiltrating or leaked data
    fn redact(&self, _output: &str) -> Option<String> { None }
}

// =====================================================================
// 2. CORE ENGINE STRUCT
// =====================================================================
#[pyclass]
pub struct ArgalaEngine {
    allowed_methods: HashSet<String>,
    plugins: Vec<Box<dyn SecurityPlugin>>,
}

impl ArgalaEngine {
    fn new_empty() -> Self {
        Self {
            allowed_methods: HashSet::new(),
            plugins: Vec::new(),
        }
    }

    // Hardened implementation processing BOTH args and kwargs
    fn inspect_impl(
        &self, 
        method_name: &str, 
        args_tuple: &Bound<'_, PyTuple>, 
        kwargs_dict: Option<&Bound<'_, PyDict>>
    ) -> PyResult<bool> {
        if !self.allowed_methods.is_empty() && !self.allowed_methods.contains(method_name) {
            return Err(PyErr::new::<ArgalaSecurityViolation, _>(format!(
                "ARGALA BLOCK: Unauthorized tool target '{}'",
                method_name
            )));
        }

        let mut extracted_strings = Vec::new();

        // 1. Extract from positional args
        for arg in args_tuple.iter() {
            if let Ok(arg_str) = arg.extract::<String>() {
                extracted_strings.push(arg_str);
            }
        }

        // 2. Extract from keyword args (Fixing the blindspot)
        if let Some(kwargs) = kwargs_dict {
            for (_key, val) in kwargs.iter() {
                if let Ok(val_str) = val.extract::<String>() {
                    extracted_strings.push(val_str);
                }
            }
        }

        // Run validation suite across all extracted inputs
        for plugin in &self.plugins {
            if let Err(violation_message) = plugin.validate(method_name, &extracted_strings) {
                return Err(PyErr::new::<ArgalaSecurityViolation, _>(format!(
                    "ARGALA BLOCK [{}] -> {}",
                    plugin.name(),
                    violation_message
                )));
            }
        }

        Ok(true)
    }
}

// =====================================================================
// 3. EXPOSED PYTHON METHODS
// =====================================================================
#[pymethods]
impl ArgalaEngine {
    #[new]
    #[pyo3(signature = (config=None))]
    fn new(config: Option<&Bound<'_, PyDict>>) -> PyResult<Self> {
        let mut engine = Self::new_empty();
        let mut enforce_defaults = true;

        if let Some(cfg) = config {
            if let Some(methods) = cfg.get_item("allowed_methods")? {
                engine.allowed_methods = methods.extract::<HashSet<String>>()?;
            }
            if let Some(val) = cfg.get_item("enforce_defaults")? {
                enforce_defaults = val.extract::<bool>()?;
            }
            if let Some(patterns) = cfg.get_item("denied_patterns")? {
                let raw_patterns = patterns.extract::<Vec<String>>()?;
                engine.plugins.push(Box::new(CustomUserPlugin::new(raw_patterns)?));
            }
        }

        if enforce_defaults {
            engine.plugins.extend(get_default_plugins());
        }

        Ok(engine)
    }

    #[classmethod]
    #[pyo3(signature = (path=None))]
    fn from_policy_file(_cls: &Bound<'_, PyType>, path: Option<&str>) -> PyResult<Self> {
        let target_path = path.unwrap_or("argala_policy.toml");
        
        if !std::path::Path::new(target_path).exists() {
            let mut engine = Self::new_empty();
            engine.plugins.extend(get_default_plugins());
            return Ok(engine);
        }

        let policy_text = fs::read_to_string(target_path).map_err(|err| {
            PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("Failed to read policy file: {}", err))
        })?;

        let parsed_policy: ArgalaTomlLayout = toml::from_str(&policy_text).map_err(|err| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Invalid TOML structure: {}", err))
        })?;

        let mut engine = Self::new_empty();
        
        if parsed_policy.argala.enforce_defaults {
            engine.plugins.extend(get_default_plugins());
        }

        let mut local_patterns = Vec::new();
        for tool_policy in parsed_policy.tools.into_values() {
            engine.allowed_methods.extend(tool_policy.allowed_methods);
            local_patterns.extend(tool_policy.denied_patterns);
        }

        if !local_patterns.is_empty() {
            engine.plugins.push(Box::new(CustomUserPlugin::new(local_patterns)?));
        }

        Ok(engine)
    }

    // Accept both args and kwargs from Python wrapper layer
    #[pyo3(signature = (method_name, args_tuple, kwargs_dict=None))]
    fn inspect_payload(
        &self, 
        method_name: &str, 
        args_tuple: &Bound<'_, PyTuple>, 
        kwargs_dict: Option<&Bound<'_, PyDict>>
    ) -> PyResult<bool> {
        self.inspect_impl(method_name, args_tuple, kwargs_dict)
    }

    // New API enabling high-speed string data leaking protection post-execution
    fn redact_output(&self, raw_output: String) -> String {
        let mut current_buffer = raw_output;
        for plugin in &self.plugins {
            if let Some(clean_string) = plugin.redact(&current_buffer) {
                current_buffer = clean_string;
            }
        }
        current_buffer
    }
}

// =====================================================================
// 4. SYSTEM INTERNAL CUSTOM AD-HOC PLUGIN
// =====================================================================
struct CustomUserPlugin {
    patterns: Vec<(String, Regex)>,
}

impl CustomUserPlugin {
    fn new(raw_patterns: Vec<String>) -> PyResult<Self> {
        let mut patterns = Vec::new();
        for p in raw_patterns {
            let regex = RegexBuilder::new(&p)
                .case_insensitive(true)
                .build()
                .map_err(|e| {
                    PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Invalid regex '{}': {}", p, e))
                })?;
            patterns.push((p, regex));
        }
        Ok(Self { patterns })
    }
}

impl SecurityPlugin for CustomUserPlugin {
    fn name(&self) -> &str {
        "user_custom_rules"
    }
    fn validate(&self, _method_name: &str, args: &[String]) -> Result<(), String> {
        for arg in args {
            for (raw_str, regex) in &self.patterns {
                if regex.is_match(arg) {
                    return Err(format!("Custom local restriction rule triggered: '{}'", raw_str));
                }
            }
        }
        Ok(())
    }
}

// =====================================================================
// 5. TOML CONFIGURATION PARSING DESERIALIZERS
// =====================================================================
#[derive(Debug, Default, Deserialize)]
struct ArgalaTomlLayout {
    #[serde(default)]
    argala: GlobalSettings,
    #[serde(default)]
    tools: HashMap<String, ToolPolicyLayout>,
}

#[derive(Debug, Deserialize)]
struct GlobalSettings {
    #[serde(default = "default_true")]
    enforce_defaults: bool,
}

impl Default for GlobalSettings {
    fn default() -> Self {
        Self { enforce_defaults: true }
    }
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Default, Deserialize)]
struct ToolPolicyLayout {
    #[serde(default)]
    allowed_methods: Vec<String>,
    #[serde(default)]
    denied_patterns: Vec<String>,
}

// =====================================================================
// 6. PYTHON FUNCTION EXTENSION & HARDENED HOOK WRAPPERS
// =====================================================================
const WRAPPER_HELPERS: &str = r#"
import functools

def make_secure_wrapper(func, engine):
    @functools.wraps(func)
    def secure_execution(*args, **kwargs):
        # Pass BOTH standard parameters and keyword values to close execution bypass vectors
        engine.inspect_payload(func.__name__, args, kwargs)
        
        # Execute actual tool logic safely
        result = func(*args, **kwargs)
        
        # Scan system results through the underlying data leakage engine before letting the agent read it
        return engine.redact_output(str(result))
    return secure_execution
"#;

#[pymodule]
fn argala(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("ArgalaSecurityViolation", py.get_type_bound::<ArgalaSecurityViolation>())?;
    m.add_class::<ArgalaEngine>()?;
    m.add_function(wrap_pyfunction!(protect_tools, m)?)?;
    Ok(())
}

#[pyfunction]
#[pyo3(signature = (tools_list, config=None))]
fn protect_tools(
    py: Python<'_>,
    tools_list: &Bound<'_, PyList>,
    config: Option<&Bound<'_, PyDict>>,
) -> PyResult<PyObject> {
    let engine = Py::new(py, ArgalaEngine::new(config)?)?;
    let wrapped_tools = PyList::empty_bound(py);

    let helpers = PyModule::from_code_bound(
        py,
        WRAPPER_HELPERS,
        "argala_helpers.py",
        "argala_helpers",
    )?;
    let make_secure_wrapper = helpers.getattr("make_secure_wrapper")?;

    for tool in tools_list.iter() {
        let wrapped = make_secure_wrapper.call1((tool, engine.clone_ref(py)))?;
        wrapped_tools.append(wrapped)?;
    }

    Ok(wrapped_tools.into_py(py))
}