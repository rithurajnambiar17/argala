use pyo3::create_exception;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList, PyModule, PyTuple, PyType};
use regex::{Regex, RegexBuilder};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::fs;

create_exception!(argala, ArgalaSecurityViolation, pyo3::exceptions::PyException);

const WRAPPER_HELPERS: &str = r#"
import functools

def make_secure_wrapper(func, engine):
    @functools.wraps(func)
    def secure_execution(*args, **kwargs):
        engine.inspect_payload(func.__name__, args)
        return func(*args, **kwargs)
    return secure_execution
"#;

#[derive(Debug, Default, Deserialize)]
struct ArgalaPolicy {
    #[serde(default)]
    tools: HashMap<String, ToolPolicy>,
}

#[derive(Debug, Default, Deserialize)]
struct ToolPolicy {
    #[serde(default)]
    allowed_methods: Vec<String>,
    #[serde(default)]
    denied_patterns: Vec<String>,
}

#[derive(Debug, Clone)]
struct DeniedPattern {
    original: String,
    regex: Regex,
}

impl DeniedPattern {
    fn compile(pattern: String) -> PyResult<Self> {
        let regex = RegexBuilder::new(&pattern)
            .case_insensitive(true)
            .build()
            .map_err(|err| {
                PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                    "Invalid denied pattern '{}': {}",
                    pattern, err
                ))
            })?;

        Ok(Self {
            original: pattern,
            regex,
        })
    }
}

/// Core engine for inspecting tool payloads.
#[pyclass]
pub struct ArgalaEngine {
    allowed_methods: HashSet<String>,
    denied_patterns: Vec<DeniedPattern>,
}

impl ArgalaEngine {
    fn from_config_dict(config: &Bound<'_, PyDict>) -> PyResult<Self> {
        let allowed_methods = match config.get_item("allowed_methods")? {
            Some(methods) => methods
                .extract::<Vec<String>>()?
                .into_iter()
                .collect::<HashSet<_>>(),
            None => HashSet::new(),
        };

        let denied_patterns = match config.get_item("denied_patterns")? {
            Some(patterns) => {
                let raw_patterns = patterns.extract::<Vec<String>>()?;
                let mut compiled_patterns = Vec::with_capacity(raw_patterns.len());

                for pattern in raw_patterns {
                    compiled_patterns.push(DeniedPattern::compile(pattern)?);
                }

                compiled_patterns
            }
            None => Vec::new(),
        };

        Ok(Self {
            allowed_methods,
            denied_patterns,
        })
    }

    fn from_policy_path(path: &str) -> PyResult<Self> {
        let policy_text = fs::read_to_string(path).map_err(|err| {
            PyErr::new::<pyo3::exceptions::PyIOError, _>(format!(
                "Failed to read policy file '{}': {}",
                path, err
            ))
        })?;

        let parsed_policy: ArgalaPolicy = toml::from_str(&policy_text).map_err(|err| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                "Invalid policy TOML in '{}': {}",
                path, err
            ))
        })?;

        let mut allowed_methods = HashSet::new();
        let mut denied_patterns = Vec::new();

        for tool_policy in parsed_policy.tools.into_values() {
            allowed_methods.extend(tool_policy.allowed_methods);

            for pattern in tool_policy.denied_patterns {
                denied_patterns.push(DeniedPattern::compile(pattern)?);
            }
        }

        Ok(Self {
            allowed_methods,
            denied_patterns,
        })
    }

    fn inspect_impl(&self, method_name: &str, args_tuple: &Bound<'_, PyTuple>) -> PyResult<bool> {
        if !self.allowed_methods.contains(method_name) {
            return Err(PyErr::new::<ArgalaSecurityViolation, _>(format!(
                "ARGALA BLOCK: Unauthorized tool target '{}'",
                method_name
            )));
        }

        for arg in args_tuple.iter() {
            if let Ok(arg_str) = arg.extract::<String>() {
                for pattern in &self.denied_patterns {
                    if pattern.regex.is_match(&arg_str) {
                        return Err(PyErr::new::<ArgalaSecurityViolation, _>(format!(
                            "ARGALA BLOCK: Destructive command anomaly detected: '{}'",
                            pattern.original
                        )));
                    }
                }
            }
        }

        Ok(true)
    }
}

#[pymethods]
impl ArgalaEngine {
    #[new]
    fn new(config: &Bound<'_, PyDict>) -> PyResult<Self> {
        Self::from_config_dict(config)
    }

    #[classmethod]
    fn from_policy_file(_cls: &Bound<'_, PyType>, path: &str) -> PyResult<Self> {
        Self::from_policy_path(path)
    }

    fn inspect_payload(&self, method_name: &str, args_tuple: &Bound<'_, PyTuple>) -> PyResult<bool> {
        self.inspect_impl(method_name, args_tuple)
    }
}

#[pyfunction]
fn protect_tools(
    py: Python<'_>,
    tools_list: &Bound<'_, PyList>,
    config: &Bound<'_, PyDict>,
) -> PyResult<PyObject> {
    let engine = Py::new(py, ArgalaEngine::from_config_dict(config)?)?;
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

/// A Python module implemented in Rust.
#[pymodule]
fn argala(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("ArgalaSecurityViolation", py.get_type_bound::<ArgalaSecurityViolation>())?;
    m.add_class::<ArgalaEngine>()?;
    m.add_function(wrap_pyfunction!(protect_tools, m)?)?;
    Ok(())
}
