/* cryptmodule.c - by Steve Majewski
 *
 * Taken from Python 3.12 with removed argument clinic code.
 */

#include "Python.h"

#include <sys/types.h>
#include <crypt.h>

/* Module crypt */

PyDoc_STRVAR(crypt_r_crypt__doc__,
"crypt($module, word, salt, /)\n"
"--\n"
"\n"
"Hash a *word* with the given *salt* and return the hashed password.\n"
"\n"
"*word* will usually be a user\'s password.  *salt* (either a random 2 or 16\n"
"character string, possibly prefixed with $digit$ to indicate the method)\n"
"will be used to perturb the encryption algorithm and produce distinct\n"
"results for a given *word*.");

static PyObject *
crypt_r_crypt(PyObject *module, PyObject *const *args, Py_ssize_t nargs)
{
    if (nargs != 2) {
        PyErr_Format(PyExc_TypeError,"crypt expected 2 arguments, got %zd", nargs);
        return NULL;
    }
    const char *word;
    const char *salt;
    Py_ssize_t word_length;
    Py_ssize_t salt_length;

    if (!PyUnicode_Check(args[0])) {
        PyErr_Format(
            PyExc_TypeError, "crypt argument 1 (word) must be string, not %s",
            Py_TYPE(args[0])->tp_name
        );
        return NULL;
    }
    word = PyUnicode_AsUTF8AndSize(args[0], &word_length);
    if (word == NULL) {
        return NULL;
    }
    if (strlen(word) != (size_t)word_length) {
        PyErr_SetString(
            PyExc_ValueError,
            "crypt argument 1 (word) contains embedded null character"
        );
        return NULL;
    }

    if (!PyUnicode_Check(args[1])) {
        PyErr_Format(
            PyExc_TypeError, "crypt argument 2 (salt) must be string, not %s",
            Py_TYPE(args[1])->tp_name
        );
        return NULL;
    }
    salt = PyUnicode_AsUTF8AndSize(args[1], &salt_length);
    if (salt == NULL) {
        return NULL;
    }
    if (strlen(salt) != (size_t)salt_length) {
        PyErr_SetString(
            PyExc_ValueError,
            "crypt argument 2 (salt) contains embedded null character"
        );
        return NULL;
    }

    char *crypt_result;
    struct crypt_data data;
    memset(&data, 0, sizeof(data));
    crypt_result = crypt_r(word, salt, &data);
    if (crypt_result == NULL) {
        return PyErr_SetFromErrno(PyExc_OSError);
    }
    return PyUnicode_FromString(crypt_result);
}


PyDoc_STRVAR(crypt_r_crypt_gensalt__doc__,
"crypt_gensalt($module, prefix, count, /)\n"
"--\n"
"\n"
"Return a setting string for the hashing method selected by *prefix*\n"
"(e.g. \"$y$\") with cost *count* (0 selects the method's default),\n"
"salted with random bytes from the operating system.\n"
"\n"
"Raises OSError with errno ENOSYS if the crypt library cannot generate\n"
"salts on its own.");

static PyObject *
crypt_r_crypt_gensalt(PyObject *module, PyObject *const *args, Py_ssize_t nargs)
{
    if (nargs != 2) {
        PyErr_Format(PyExc_TypeError, "crypt_gensalt expected 2 arguments, got %zd", nargs);
        return NULL;
    }
    const char *prefix;
    Py_ssize_t prefix_length;
    unsigned long count;

    if (!PyUnicode_Check(args[0])) {
        PyErr_Format(
            PyExc_TypeError, "crypt_gensalt argument 1 (prefix) must be string, not %s",
            Py_TYPE(args[0])->tp_name
        );
        return NULL;
    }
    prefix = PyUnicode_AsUTF8AndSize(args[0], &prefix_length);
    if (prefix == NULL) {
        return NULL;
    }
    if (strlen(prefix) != (size_t)prefix_length) {
        PyErr_SetString(
            PyExc_ValueError,
            "crypt_gensalt argument 1 (prefix) contains embedded null character"
        );
        return NULL;
    }

    count = PyLong_AsUnsignedLong(args[1]);
    if (count == (unsigned long)-1 && PyErr_Occurred()) {
        return NULL;
    }

#ifdef CRYPT_GENSALT_IMPLEMENTS_AUTO_ENTROPY
    char output[CRYPT_GENSALT_OUTPUT_SIZE];
    if (crypt_gensalt_rn(prefix, count, NULL, 0, output, sizeof(output)) == NULL) {
        return PyErr_SetFromErrno(PyExc_OSError);
    }
    return PyUnicode_FromString(output);
#else
    errno = ENOSYS;
    return PyErr_SetFromErrno(PyExc_OSError);
#endif
}


static PyMethodDef crypt_r_methods[] = {
    {"crypt", (PyCFunction)crypt_r_crypt, METH_FASTCALL, crypt_r_crypt__doc__},
    {"crypt_gensalt", (PyCFunction)crypt_r_crypt_gensalt, METH_FASTCALL, crypt_r_crypt_gensalt__doc__},
    {NULL,              NULL}           /* sentinel */
};

static PyModuleDef_Slot _crypt_r_slots[] = {
#ifdef Py_MOD_PER_INTERPRETER_GIL_SUPPORTED
    {Py_mod_multiple_interpreters, Py_MOD_PER_INTERPRETER_GIL_SUPPORTED},
#endif
    {0, NULL}
};

static struct PyModuleDef crypt_r_module = {
    PyModuleDef_HEAD_INIT,
    "_crypt_r",
    NULL,
    0,
    crypt_r_methods,
    _crypt_r_slots,
    NULL,
    NULL,
    NULL
};

PyMODINIT_FUNC
PyInit__crypt_r(void)
{
    return PyModuleDef_Init(&crypt_r_module);
}
