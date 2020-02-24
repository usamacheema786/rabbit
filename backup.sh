#!/bin/bash
mysqldump -uroot -pd1d5c3ff-95cb-47a7-b5de-9412a707f428 doosradb > doosradb_$(date +%Y-%b-%d_%H:%M:%S).sql