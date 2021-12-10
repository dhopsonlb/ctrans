#!/usr/bin/env python
# -*- coding: utf-8 -*-
# using Python 2.7!
# translates comments in code
# google translate portions are cleaned up from
# http://www.halotis.com/2009/09/15/google-translate-api-python-script/
# everything else written by Kyle Isom <coder@kyleisom.net>
# usage:
# ./ctrans.py -s filename
#	 will translate a single file

# Updated 2020-03-02 by William Cable to use Google Cloud Translation
# because the old ajax api wasn't working anymore

# Setup Cloud Console project and download credentials
# https://cloud.google.com/translate/docs/basic/setup-basic
# set path to credentials:
# $env:GOOGLE_APPLICATION_CREDENTIALS="B:\AWI\Python\ctrans\Python Translate-50994b9b6934.json"


# sudo pip install googletrans==3.1.0a0
# https://github.com/ssut/py-googletrans/issues/280
from googletrans import Translator

import chardet
import codecs
import getopt
import multiprocessing
import os
import re
import sys
import urllib.request, urllib.parse, urllib.error



### globals ###

translator = Translator()

# variables from halotis' code
lang = 'en'  # Target Language
lang_src = 'auto'  # Source Language, 'auto' for auto-detect

# misc vars
trace = False  # enable debugging output
ext = '.en'  # extension of translated files
num_procs = 32  # number of concurrent processes

# coding vars
encodeas = 'utf-8'  # input file type
decodeas = 'utf-8'  # output file type
cerr = 'strict'  # what do with codec errors
autodetect = True  # autodetect file encoding

# regexes for the different comment types
scrub_bcomments = re.compile(r'/\*([\s\S]+?)\*/', re.M & re.U)
scrub_lcomments = re.compile(r'//(.+)', re.U & re.M)
scrub_scomments = re.compile(r'#\s*(.+)', re.U & re.M)

# extensions for valid source files
source_exts = {
	'c-style': ['c', 'cpp', 'cc', 'h', 'hpp'],
	'script': ['py', 'pl', 'rb']
}


def get_splits(text, splitLength = 4500):
	"""
	Translate Api has a limit on length of text(4500 characters) that can be
	translated at once,
	"""
	return (
		text[index:index + splitLength]
		for index in range(0, len(text), splitLength)
	)


def translate(text):
	"""
	Translate using Googles API
	"""

	retText = ''

	for text in get_splits(text):
		if trace:
			print('[+] translation requested...')
		sys.stdout.flush()

		resp = translator.translate(
			text,
			dest=lang,
			src=lang_src,
		)

		try:
			retText += resp['translatedText']
		except:
			retText += text
		if trace:
			print('\treceived!')

	return retText

### start kyle's code ###

## handle C-style comments

# handles /* \w+ */ comments
def trans_block_comment(comment):
	# comment should be arrive as a re.Match object, need to grab the group
	trans = str(comment.group())
	trans = trans.split('\n')

	# translate each line and compensate for the fact that gtrans eats your
	# formatting
	trans = [translate(line) for line in trans]
	trans = [line.replace('/ * ', '/* ') for line in trans]
	trans = [line.replace(' * /', ' */') for line in trans]
	comment = '\n'.join(trans)

	sys.stdout.write("B"); sys.stdout.flush()

	# here's your stupid translation
	return comment

# handle // \w+ comments
def trans_line_comment(comment):
	trans = str(comment.group())
	if trace:
		print((trans.encode('utf-8')))
	trans = trans.lstrip('//')
	trans = translate(trans.strip())
	comment = '// %s' % trans

	sys.stdout.write("L"); sys.stdout.flush()

	return comment


## handle non-C-style comments

# handle an initial '#', like in perl or python or your mom
def trans_scripting_comment(comment):
	trans = str(comment.group())

	if trans.startswith('#!'):
		return trans

	trans = trans.lstrip('#')
	trans = translate(trans.strip())
	comment = '# %s' % trans

	return comment


### processing code ###
# the following functions handle regexes, file tree walking and file I/O

# guess the encoding on a file
# returns a string with the encoding if it is confident in its guess,
#	 False otherwise
# detection threshhold is confidence required to return an encoding
#
# design note: returns a string instead of globally modifying the encodeas var
# to support concurrency - the memory of duplicating a short string containing
# the encoding is low enough to not cause a performance hit and prevents the
# code from having to involve locking or shared memory.
def guess_encoding(filename, detection_threshold=0.8, return_dict=False):
	if trace:
		print('[+] attempting to autodetect coding for %s' % filename)
	try:
		f = open(filename, 'rb')
		guess = chardet.detect(f.read())
		f.close()
	except IOError as e:
		if trace:
			print('[!] error on file %s, skipping...' % filename)
		print('\t(error returned was %s)' % str(e))
		if not return_tuple:
			return False

	confidence = '%0.1f' % guess['confidence']
	confidence = float(confidence)

	if confidence < detection_threshold:
		print('[!] too low of a confidence (%f) to guess coding for %s' % (
			guess['confidence'],
			filename
		))
		return False
	else:
		if trace:
			print('[+] detected coding %s for file %s (confidence: %0.2f)' % (
				guess['encoding'],
				filename,
				guess['confidence']
			))
		return guess['encoding'] if not return_dict else {
			'encoding': guess['encoding'],
			'confidence': guess['confidence'],
		}


# attempt to guess dir
def guess_dir(dir):
	walk = os.walk(dir)
	codes = { }
	codec_scan = []

	while True:
		try:
			(dirp, dirs, files) = next(walk)
		except StopIteration as e:
			break
		else:
			codec_scan.extend([
				os.path.join(dirp, file) for file in files
				if is_source(os.path.join(dirp, file))
				or is_script(os.path.join(dirp, file))
			])
	for filename in codec_scan:
		guess = guess_encoding(filename, return_dict=True)
		encoding, confidence = guess['encoding'], guess['confidence']

		if encoding in codes:
			codes[encoding] += confidence
		else:
			codes[encoding] = confidence

	return list(sorted(
		codes,
		key=lambda x: codes[x],
		reverse=True
	))[0]


# translate an individual file
def scan_file(filename):
	new_filename = filename + ext

	# the reason we use a local variable for the encoding based on either
	# the guess_encoding() function or a copy of the encodeas global is
	# detailed more in the design note in the comments for guess_encoding -
	# the tl;dr is it solves some concurrency issues without incurring any
	# major penalties.
	if autodetect:
		encoding = guess_encoding(filename)
		if not encoding:
			print('[!] could not reliably determine encoding for %s' % filename)
			print('\taborting!')
			return
	else:
		encoding = encodeas

	try:
		# read old source file
		reader = codecs.open(
			filename,
			mode='r',
			encoding=encoding,
			errors='replace'
		)
		ucode = reader.read()  # untranslated code
		# write translated
		writer = codecs.open(
			new_filename,
			mode='w',
			encoding=decodeas,
		)
		reader.close()
	except IOError as e:  # abort on IO error
		print('[!] error on file %s, skipping...' % filename)
		print('\t(error returned was %s)' % str(e))
		return None

	if not ucode:
		return None

	if is_source(filename):
		tcode = scrub_bcomments.sub(trans_block_comment, ucode)
		tcode = scrub_lcomments.sub(trans_line_comment, tcode)
	elif is_script(filename):
		tcode = scrub_scomments.sub(trans_scripting_comment, ucode)

	writer.write(tcode)

	print('[+] translated %s to %s...' % (filename, new_filename))

# look through a directory
def scan_dir(dirname):
	global autodetect  # used to tweak better file encoding
	global encodeas  # scans

	scanner = os.walk(dirname, topdown=True)
	pool = multiprocessing.Pool(processes=num_procs)
	file_list = []

	if autodetect:
		encodeas = guess_dir(dirname)
		autodetect = False

	while True:
		try:
			scan_t = next(scanner)  # scan_t: (dirp, dirs, files)
		except StopIteration:
			break
		else:
			for f in scan_t[2]:
				file_list.append(os.path.join(scan_t[0], f))

	scan_list = [
		os.path.join(scan_t[0], file) for file in file_list
		if is_source(file) or is_script(file)
	]

	dev = 1

	pool.map(scan_file, scan_list)
	pool.close()
	pool.join()

# detect c-style comments
def is_source(filename):
	extension = re.sub('^.+\\.(\\w+)$', '\\1', filename)
	if extension in source_exts['c-style']:
		return True

	return False

# detect script-style comments
def is_script(filename):
	extension = re.sub('^.+\\.(\\w+)$', '\\1', filename)
	if extension in source_exts['script']:
		return True

	return False

##### start main code #####
if __name__ == '__main__':
	opts, args = getopt.getopt(sys.argv[1:], 's:d:e:o:t')
	dir_mode = False
	target = None

	for (opt, arg) in opts:
		if opt == '-s':
			dir_mode = False
			target = arg
		if opt == '-d':
			dir_mode = True
			target = arg
		if opt == '-e':
			if not arg == 'auto':
				encodeas = arg
			else:
				autodetect = True
		if opt == '-o':
			decodeas = arg


	if dir_mode:
		scan_dir(target)
	else:
		scan_file(target)


