/* cryptmodule.c - by Steve Majewski
 *
 * Taken from Python 3.12 with removed argument clinic code.
 */

#include "Python.h"

#include <sys/types.h>
#ifdef HAVE_CRYPT_H
#include <crypt.h>
#endif

/* Module crypt */

PyDoc_STRVAR(crypt_crypt__doc__,
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
crypt_crypt(PyObject *module, PyObject *const *args, Py_ssize_t nargs)
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
#ifdef HAVE_CRYPT_R
    struct crypt_data data;
    memset(&data, 0, sizeof(data));
    crypt_result = crypt_r(word, salt, &data);
#else
    crypt_result = crypt(word, salt);
#endif
    if (crypt_result == NULL) {
        return PyErr_SetFromErrno(PyExc_OSError);
    }
    return PyUnicode_FromString(crypt_result);
}


static PyMethodDef crypt_methods[] = {
    {"crypt", crypt_crypt, METH_FASTCALL, crypt_crypt__doc__},
    {NULL,              NULL}           /* sentinel */
};

static PyModuleDef_Slot _crypt_slots[] = {
#ifdef Py_MOD_PER_INTERPRETER_GIL_SUPPORTED
    {Py_mod_multiple_interpreters, Py_MOD_PER_INTERPRETER_GIL_SUPPORTED},
#endif
    {0, NULL}
};

static struct PyModuleDef cryptmodule = {
    PyModuleDef_HEAD_INIT,
    "_crypt",
    NULL,
    0,
    crypt_methods,
    _crypt_slots,
    NULL,
    NULL,
    NULL
};

PyMODINIT_FUNC
PyInit__crypt(void)
{
    return PyModuleDef_Init(&cryptmodule);
}
