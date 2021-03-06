{*
Copyright 2012-2017 Nick Korbel

This file is part of Booked Scheduler.

Booked Scheduler is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Booked Scheduler is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Booked Scheduler.  If not, see <http://www.gnu.org/licenses/>.
*}
{foreach from=$Definition->GetColumnHeaders() item=column name=columnIterator}{if $ReportCsvColumnView->ShouldShowCol($column, $smarty.foreach.columnIterator.index)}"{if $column->HasTitle()}{$column->Title()}{else}{translate key=$column->TitleKey()}{/if}",{/if}{/foreach}

{foreach from=$Report->GetData()->Rows() item=row}{foreach from=$Definition->GetRow($row) item=data name=dataIterator}{if $ReportCsvColumnView->ShouldShowCell($smarty.foreach.dataIterator.index)}"{$data->Value()|escape}",{/if}{/foreach}

{/foreach}